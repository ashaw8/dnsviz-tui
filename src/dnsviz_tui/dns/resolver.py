"""DNS resolver for querying DNSSEC records."""

import time
from typing import Optional

import dns.name
import dns.query
import dns.resolver
import dns.rdatatype
import dns.message
import dns.flags
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG

from dnsviz_tui.dns.records import RecordFormatter
from dnsviz_tui.models.chain import (
    ZoneInfo,
    AdditionalRecord,
    ValidationStatus,
)


class DNSResolver:
    """DNS resolver for DNSSEC chain of trust queries."""

    # Default resolvers to try
    DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def __init__(self, nameservers: Optional[list[str]] = None):
        """Initialize the resolver.

        Args:
            nameservers: List of nameserver IPs to use. If None, uses system default.
        """
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
        self._formatter = RecordFormatter()

    @property
    def nameservers(self) -> list[str]:
        """Get current nameservers."""
        return self.resolver.nameservers

    def set_nameservers(self, nameservers: list[str]) -> None:
        """Set nameservers to use."""
        self.resolver.nameservers = nameservers

    def _query(
        self,
        name: str,
        rdtype: str,
        raise_on_nxdomain: bool = False,
    ) -> Optional[dns.resolver.Answer]:
        """Perform a DNS query.

        Args:
            name: Domain name to query
            rdtype: Record type (e.g., "DNSKEY", "DS")
            raise_on_nxdomain: Whether to raise on NXDOMAIN

        Returns:
            Answer object or None if no records found
        """
        try:
            answer = self.resolver.resolve(name, rdtype, raise_on_no_answer=False)
            return answer
        except dns.resolver.NXDOMAIN:
            if raise_on_nxdomain:
                raise
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NoNameservers:
            return None
        except dns.resolver.Timeout:
            return None
        except dns.exception.DNSException:
            return None
        except Exception:
            return None

    def query_dnskeys(self, zone: str) -> ZoneInfo:
        """Query DNSKEY records for a zone.

        Args:
            zone: Zone name (e.g., "example.com.")

        Returns:
            ZoneInfo with DNSKEY records populated
        """
        zone_info = ZoneInfo(name=zone)

        # Query DNSKEY
        answer = self._query(zone, "DNSKEY")
        if answer:
            for rdata in answer:
                if isinstance(rdata, DNSKEY):
                    key_info = self._formatter.parse_dnskey(rdata)
                    zone_info.dnskeys.append(key_info)

            # Get RRSIGs for DNSKEY
            if answer.response:
                for rrset in answer.response.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        for rdata in rrset:
                            if isinstance(rdata, RRSIG) and rdata.type_covered == dns.rdatatype.DNSKEY:
                                rrsig_info = self._formatter.parse_rrsig(rdata)
                                zone_info.rrsigs.append(rrsig_info)

        return zone_info

    def query_ds(self, zone: str) -> list:
        """Query DS records for a zone from its parent.

        Args:
            zone: Zone name (e.g., "example.com.")

        Returns:
            List of DSInfo objects
        """
        ds_records = []
        answer = self._query(zone, "DS")
        if answer:
            for rdata in answer:
                if isinstance(rdata, DS):
                    ds_info = self._formatter.parse_ds(rdata)
                    ds_records.append(ds_info)
        return ds_records

    def query_additional_records(self, domain: str) -> list[AdditionalRecord]:
        """Query additional records for a domain (SPF, DMARC, etc.).

        Args:
            domain: Domain name

        Returns:
            List of AdditionalRecord objects
        """
        records = []

        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'

        # Query common record types
        record_queries = [
            (domain, "A"),
            (domain, "AAAA"),
            (domain, "MX"),
            (domain, "TXT"),  # Includes SPF
            (f"_dmarc.{domain}", "TXT"),  # DMARC
        ]

        for name, rdtype in record_queries:
            try:
                answer = self._query(name, rdtype)
                if answer:
                    # Check for RRSIG
                    has_rrsig = False
                    rrsig_info = None
                    if answer.response:
                        for rrset in answer.response.answer:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                for rdata in rrset:
                                    if isinstance(rdata, RRSIG):
                                        has_rrsig = True
                                        rrsig_info = self._formatter.parse_rrsig(rdata)
                                        break

                    for rdata in answer:
                        # Determine record type label
                        record_type = rdtype
                        value = str(rdata)

                        # Identify SPF records
                        if rdtype == "TXT" and "v=spf1" in value.lower():
                            record_type = "SPF"

                        # Identify DMARC records
                        if "_dmarc" in name and "v=dmarc1" in value.lower():
                            record_type = "DMARC"

                        record = AdditionalRecord(
                            record_type=record_type,
                            name=name,
                            value=value.strip('"'),
                            ttl=answer.rrset.ttl if answer.rrset else 0,
                            is_signed=has_rrsig,
                            rrsig=rrsig_info,
                        )
                        records.append(record)
            except Exception:
                continue

        return records

    def get_zone_hierarchy(self, domain: str) -> list[str]:
        """Get the zone hierarchy from root to domain.

        Args:
            domain: Target domain (e.g., "www.example.com")

        Returns:
            List of zone names from root to domain
            (e.g., [".", "com.", "example.com."])
        """
        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'

        # Split into labels (e.g., "www.example.com." -> ["www", "example", "com", ""])
        parts = domain.rstrip('.').split('.')

        # Build hierarchy from root to target
        # For "devries.tv" -> [".", "tv.", "devries.tv."]
        zones = ["."]  # Always start with root

        # Build each zone level
        for i in range(len(parts) - 1, -1, -1):
            zone = ".".join(parts[i:]) + "."
            if zone != "." and zone not in zones:
                zones.append(zone)

        return zones

    def query_zone_chain(self, domain: str) -> tuple[list[ZoneInfo], float]:
        """Query the complete DNSSEC chain for a domain.

        Args:
            domain: Target domain

        Returns:
            Tuple of (list of ZoneInfo objects, query time in ms)
        """
        start_time = time.time()
        zones = []
        hierarchy = self.get_zone_hierarchy(domain)

        for i, zone_name in enumerate(hierarchy):
            zone_info = self.query_dnskeys(zone_name)

            # Set parent zone
            if i > 0:
                zone_info.parent = hierarchy[i - 1]

            # Query DS records (not for root)
            if zone_name != ".":
                zone_info.ds_records = self.query_ds(zone_name)

            # For the target domain, also get additional records
            if zone_name == hierarchy[-1] or domain.rstrip('.') + '.' == zone_name:
                zone_info.additional_records = self.query_additional_records(domain)

            zones.append(zone_info)

        query_time = (time.time() - start_time) * 1000
        return zones, query_time
