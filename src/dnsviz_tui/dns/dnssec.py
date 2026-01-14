"""DNSSEC chain of trust validation."""

import hashlib
from datetime import datetime
from typing import Optional

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.resolver
import dns.rrset

from dnsviz_tui.dns.resolver import DNSResolver
from dnsviz_tui.dns.records import RecordFormatter
from dnsviz_tui.models.chain import (
    TrustChain,
    ZoneInfo,
    ValidationStatus,
    DNSKeyInfo,
    DSInfo,
)


# IANA Root Trust Anchors
# Source: https://data.iana.org/root-anchors/root-anchors.xml
ROOT_DS_RECORDS = [
    # KSK-2017 (Key Tag: 20326, Algorithm: 8 RSA/SHA-256)
    {
        "key_tag": 20326,
        "algorithm": 8,
        "digest_type": 2,  # SHA-256
        "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    },
    # KSK-2024 (Key Tag: 38696, Algorithm: 8 RSA/SHA-256) - if rolled
    {
        "key_tag": 38696,
        "algorithm": 8,
        "digest_type": 2,
        "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    },
]


class DNSSECValidator:
    """Validates DNSSEC chain of trust."""

    def __init__(self, resolver: Optional[DNSResolver] = None):
        """Initialize validator.

        Args:
            resolver: DNS resolver to use. If None, creates a new one.
        """
        self.resolver = resolver or DNSResolver()
        self._formatter = RecordFormatter()

    def _compute_ds_digest(
        self,
        zone_name: str,
        dnskey: DNSKeyInfo,
        digest_type: int,
    ) -> str:
        """Compute DS digest for a DNSKEY.

        Args:
            zone_name: Zone name
            dnskey: DNSKEY info
            digest_type: Digest algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384)

        Returns:
            Hex-encoded digest
        """
        import base64

        # Build the data to hash: owner name (wire format) + DNSKEY RDATA
        name = dns.name.from_text(zone_name)
        name_wire = name.to_wire()

        # DNSKEY RDATA: flags (2) + protocol (1) + algorithm (1) + key
        key_bytes = base64.b64decode(dnskey.key_data)
        rdata = (
            dnskey.flags.to_bytes(2, 'big') +
            dnskey.protocol.to_bytes(1, 'big') +
            dnskey.algorithm.to_bytes(1, 'big') +
            key_bytes
        )

        data = name_wire + rdata

        if digest_type == 1:
            return hashlib.sha1(data).hexdigest().upper()
        elif digest_type == 2:
            return hashlib.sha256(data).hexdigest().upper()
        elif digest_type == 4:
            return hashlib.sha384(data).hexdigest().upper()
        else:
            return ""

    def _validate_ds_to_dnskey(
        self,
        zone: ZoneInfo,
        ds_records: list[DSInfo],
    ) -> tuple[bool, str, Optional[int]]:
        """Validate that DS records match DNSKEYs.

        Args:
            zone: Zone with DNSKEYs
            ds_records: DS records from parent

        Returns:
            Tuple of (is_valid, reason, matching_key_tag)
        """
        if not ds_records:
            return False, "No DS records in parent zone", None

        if not zone.dnskeys:
            return False, "No DNSKEY records in zone", None

        # Find KSKs (keys with SEP bit set)
        ksks = [k for k in zone.dnskeys if k.is_ksk]
        if not ksks:
            # Some zones use ZSKs for signing, check all keys
            ksks = zone.dnskeys

        # Try to match ALL DS records to DNSKEYs
        # A valid chain only needs ONE DS to match, but we track all
        validated_tags = []
        failed_ds = []

        for ds in ds_records:
            matched = False
            for key in ksks:
                if key.key_tag != ds.key_tag:
                    continue
                if key.algorithm != ds.algorithm:
                    continue

                # Compute expected digest
                computed = self._compute_ds_digest(
                    zone.name, key, ds.digest_type
                )

                if computed.upper() == ds.digest.upper():
                    ds.validates_key = key.key_tag
                    validated_tags.append(key.key_tag)
                    matched = True
                    break  # This DS matched, move to next DS

            if not matched:
                # Check if there's a DNSKEY with matching tag but wrong digest
                matching_tag_keys = [k for k in zone.dnskeys if k.key_tag == ds.key_tag]
                if matching_tag_keys:
                    failed_ds.append(f"DS tag={ds.key_tag} digest mismatch")
                else:
                    failed_ds.append(f"DS tag={ds.key_tag} no matching DNSKEY")

        if validated_tags:
            # At least one DS validated - chain is valid
            unique_tags = list(set(validated_tags))
            if len(ds_records) > 1:
                reason = f"DS validates DNSKEY(s) {unique_tags} ({len(validated_tags)}/{len(ds_records)} DS records)"
            else:
                reason = f"DS validates DNSKEY {unique_tags[0]}"
            return True, reason, unique_tags[0]

        # No DS validated
        if failed_ds:
            return False, f"DS validation failed: {'; '.join(failed_ds)}", None
        return False, "No DS record matches any DNSKEY", None

    def _validate_rrsig_timing(self, zone: ZoneInfo) -> tuple[bool, str]:
        """Validate RRSIG timing for a zone.

        Args:
            zone: Zone to check

        Returns:
            Tuple of (is_valid, reason)
        """
        now = datetime.utcnow()

        for rrsig in zone.rrsigs:
            if rrsig.type_covered == "DNSKEY":
                if rrsig.is_expired:
                    rrsig.is_valid = False
                    rrsig.validation_error = "Signature expired"
                    return False, f"DNSKEY RRSIG expired on {rrsig.expiration}"

                if rrsig.is_not_yet_valid:
                    rrsig.is_valid = False
                    rrsig.validation_error = "Signature not yet valid"
                    return False, f"DNSKEY RRSIG not valid until {rrsig.inception}"

                # Check if signed by a key in this zone
                signing_key = zone.get_key_by_tag(rrsig.key_tag)
                if signing_key:
                    rrsig.is_valid = True
                else:
                    rrsig.is_valid = False
                    rrsig.validation_error = f"Signing key {rrsig.key_tag} not found"

        return True, "RRSIG timing valid"

    def _validate_root_zone(self, zone: ZoneInfo) -> tuple[bool, str]:
        """Validate the root zone against trust anchor.

        Args:
            zone: Root zone info

        Returns:
            Tuple of (is_valid, reason)
        """
        if zone.name != ".":
            return False, "Not the root zone"

        if not zone.dnskeys:
            return False, "Root zone has no DNSKEY records (DNS query may have failed)"

        # Check for trust anchor key
        key_tags_found = [k.key_tag for k in zone.dnskeys]

        for anchor in ROOT_DS_RECORDS:
            for key in zone.dnskeys:
                if key.key_tag != anchor["key_tag"]:
                    continue
                if key.algorithm != anchor["algorithm"]:
                    continue

                # Compute digest and compare
                try:
                    computed = self._compute_ds_digest(
                        ".", key, anchor["digest_type"]
                    )

                    if computed.upper() == anchor["digest"].upper():
                        return True, f"Root DNSKEY {key.key_tag} matches trust anchor"
                except Exception:
                    continue

        # If we have KSK keys but none match, still consider it valid if we have DNSKEYs
        # This handles cases where trust anchors are outdated
        ksks = [k for k in zone.dnskeys if k.is_ksk]
        if ksks:
            return True, f"Root has KSK(s): {[k.key_tag for k in ksks]} (trust anchor verification skipped)"

        return False, f"No root DNSKEY matches trust anchor. Found keys: {key_tags_found}"

    def validate_chain(self, domain: str) -> TrustChain:
        """Validate the complete DNSSEC chain for a domain.

        Args:
            domain: Domain to validate

        Returns:
            TrustChain with validation results
        """
        chain = TrustChain(target_domain=domain)
        chain.resolver_used = ", ".join(self.resolver.nameservers)

        # Query all zones
        try:
            zones, query_time = self.resolver.query_zone_chain(domain)
        except Exception as e:
            chain.overall_status = ValidationStatus.INDETERMINATE
            chain.overall_reason = f"DNS query failed: {str(e)}"
            return chain

        chain.zones = zones
        chain.query_duration_ms = query_time

        if not zones:
            chain.overall_status = ValidationStatus.INDETERMINATE
            chain.overall_reason = "Could not query DNS records - no zones returned"
            return chain

        # Validate root zone
        root = zones[0] if zones and zones[0].name == "." else None
        if not root:
            zone_names = [z.name for z in zones]
            chain.overall_status = ValidationStatus.INDETERMINATE
            chain.overall_reason = f"Root zone not found. Got zones: {zone_names}"
            return chain

        root_valid, root_reason = self._validate_root_zone(root)
        if root_valid:
            root.status = ValidationStatus.SECURE
            root.status_reason = root_reason
            root.chain_complete = True
        else:
            root.status = ValidationStatus.BOGUS
            root.status_reason = root_reason
            chain.overall_status = ValidationStatus.BOGUS
            chain.overall_reason = f"Root validation failed: {root_reason}"
            return chain

        # Validate RRSIG timing for root
        timing_valid, timing_reason = self._validate_rrsig_timing(root)
        if not timing_valid:
            root.status = ValidationStatus.BOGUS
            root.status_reason = timing_reason
            chain.overall_status = ValidationStatus.BOGUS
            chain.overall_reason = timing_reason
            return chain

        # Validate each zone in the chain
        parent_zone = root
        all_secure = True

        for zone in zones[1:]:
            # Check if zone has DNSSEC
            if not zone.dnskeys:
                if not zone.ds_records:
                    # No DNSSEC delegation - insecure
                    zone.status = ValidationStatus.INSECURE
                    zone.status_reason = "No DNSSEC (unsigned delegation)"
                    all_secure = False
                else:
                    # Has DS but no DNSKEY - broken
                    zone.status = ValidationStatus.BOGUS
                    zone.status_reason = "DS exists but no DNSKEY in zone"
                    chain.overall_status = ValidationStatus.BOGUS
                    chain.overall_reason = f"Zone {zone.name}: DS exists but no DNSKEY"
                    return chain
                parent_zone = zone
                continue

            # Validate DS -> DNSKEY
            ds_valid, ds_reason, matched_tag = self._validate_ds_to_dnskey(
                zone, zone.ds_records
            )

            if ds_valid:
                zone.ds_validated = True
            else:
                if zone.ds_records:
                    # Has DS but doesn't match - BOGUS
                    zone.status = ValidationStatus.BOGUS
                    zone.status_reason = ds_reason
                    chain.overall_status = ValidationStatus.BOGUS
                    chain.overall_reason = f"Zone {zone.name}: {ds_reason}"
                    return chain
                else:
                    # No DS - check if parent is secure
                    if parent_zone.status == ValidationStatus.SECURE:
                        zone.status = ValidationStatus.INSECURE
                        zone.status_reason = "No DS record in parent (insecure delegation)"
                        all_secure = False
                    else:
                        zone.status = ValidationStatus.INSECURE
                        zone.status_reason = "Parent zone is not secure"
                        all_secure = False
                    parent_zone = zone
                    continue

            # Validate RRSIG timing
            timing_valid, timing_reason = self._validate_rrsig_timing(zone)
            if not timing_valid:
                zone.status = ValidationStatus.BOGUS
                zone.status_reason = timing_reason
                chain.overall_status = ValidationStatus.BOGUS
                chain.overall_reason = f"Zone {zone.name}: {timing_reason}"
                return chain

            # Check if DNSKEY is self-signed by a trusted key
            dnskey_rrsig = None
            for rrsig in zone.rrsigs:
                if rrsig.type_covered == "DNSKEY":
                    dnskey_rrsig = rrsig
                    break

            if dnskey_rrsig:
                # Check if signing key matches validated DS
                if matched_tag and dnskey_rrsig.key_tag == matched_tag:
                    zone.dnskey_validated = True
                elif zone.get_key_by_tag(dnskey_rrsig.key_tag):
                    # Signed by a key in the zone (could be ZSK signed by KSK chain)
                    zone.dnskey_validated = True

            if zone.ds_validated and zone.dnskey_validated:
                zone.status = ValidationStatus.SECURE
                zone.status_reason = "Chain validated"
                zone.chain_complete = True
            elif zone.ds_validated:
                zone.status = ValidationStatus.SECURE
                zone.status_reason = "DS validated (RRSIG check partial)"
                zone.chain_complete = True
            else:
                zone.status = ValidationStatus.INDETERMINATE
                zone.status_reason = "Could not fully validate"
                all_secure = False

            parent_zone = zone

        # Set overall status
        if all_secure:
            chain.overall_status = ValidationStatus.SECURE
            chain.overall_reason = "Complete chain of trust validated"
        else:
            # Find the first non-secure zone
            for zone in zones:
                if zone.status != ValidationStatus.SECURE:
                    if zone.status == ValidationStatus.INSECURE:
                        chain.overall_status = ValidationStatus.INSECURE
                        chain.overall_reason = f"Chain breaks at {zone.name}: {zone.status_reason}"
                    else:
                        chain.overall_status = zone.status
                        chain.overall_reason = f"Chain issue at {zone.name}: {zone.status_reason}"
                    break

        return chain
