"""DNS record type definitions and parsing utilities."""

import base64
from datetime import datetime
from typing import Optional

import dns.dnssec
import dns.rdatatype
import dns.rdata
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.NSEC3 import NSEC3

from dnsviz_tui.models.chain import (
    DNSKeyInfo,
    DSInfo,
    RRSIGInfo,
    NSECInfo,
    AdditionalRecord,
)


# Algorithm name mapping
ALGORITHM_NAMES = {
    1: "RSA/MD5",
    3: "DSA/SHA-1",
    5: "RSA/SHA-1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "ECC-GOST",
    13: "ECDSA/P-256/SHA-256",
    14: "ECDSA/P-384/SHA-384",
    15: "Ed25519",
    16: "Ed448",
}

# Digest type mapping
DIGEST_TYPE_NAMES = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384",
}

# Key length estimation based on algorithm
def estimate_key_length(algorithm: int, key_data: bytes) -> int:
    """Estimate key length in bits based on algorithm and key data."""
    key_len = len(key_data) * 8

    # RSA keys have specific structure
    if algorithm in (1, 5, 7, 8, 10):
        # RSA: subtract exponent length indicator and exponent
        if key_data[0] == 0:
            exp_len = (key_data[1] << 8) | key_data[2]
            return (len(key_data) - 3 - exp_len) * 8
        else:
            exp_len = key_data[0]
            return (len(key_data) - 1 - exp_len) * 8

    # ECDSA P-256
    if algorithm == 13:
        return 256

    # ECDSA P-384
    if algorithm == 14:
        return 384

    # Ed25519
    if algorithm == 15:
        return 256

    # Ed448
    if algorithm == 16:
        return 448

    return key_len


class RecordFormatter:
    """Utility class for formatting DNS records for display."""

    @staticmethod
    def parse_dnskey(rdata: DNSKEY) -> DNSKeyInfo:
        """Parse a DNSKEY record into DNSKeyInfo."""
        key_bytes = rdata.key
        key_b64 = base64.b64encode(key_bytes).decode('ascii')

        return DNSKeyInfo(
            flags=rdata.flags,
            protocol=rdata.protocol,
            algorithm=rdata.algorithm,
            algorithm_name=ALGORITHM_NAMES.get(rdata.algorithm, f"Unknown ({rdata.algorithm})"),
            key_tag=dns.dnssec.key_id(rdata),
            key_data=key_b64,
            key_length=estimate_key_length(rdata.algorithm, key_bytes),
        )

    @staticmethod
    def parse_ds(rdata: DS) -> DSInfo:
        """Parse a DS record into DSInfo."""
        return DSInfo(
            key_tag=rdata.key_tag,
            algorithm=rdata.algorithm,
            algorithm_name=ALGORITHM_NAMES.get(rdata.algorithm, f"Unknown ({rdata.algorithm})"),
            digest_type=rdata.digest_type,
            digest_type_name=DIGEST_TYPE_NAMES.get(rdata.digest_type, f"Unknown ({rdata.digest_type})"),
            digest=rdata.digest.hex().upper(),
        )

    @staticmethod
    def parse_rrsig(rdata: RRSIG) -> RRSIGInfo:
        """Parse an RRSIG record into RRSIGInfo."""
        # Convert timestamps
        expiration = datetime.utcfromtimestamp(rdata.expiration)
        inception = datetime.utcfromtimestamp(rdata.inception)

        return RRSIGInfo(
            type_covered=dns.rdatatype.to_text(rdata.type_covered),
            algorithm=rdata.algorithm,
            algorithm_name=ALGORITHM_NAMES.get(rdata.algorithm, f"Unknown ({rdata.algorithm})"),
            labels=rdata.labels,
            original_ttl=rdata.original_ttl,
            expiration=expiration,
            inception=inception,
            key_tag=rdata.key_tag,
            signer_name=str(rdata.signer),
            signature=base64.b64encode(rdata.signature).decode('ascii'),
        )

    @staticmethod
    def parse_nsec(rdata: NSEC) -> NSECInfo:
        """Parse an NSEC record into NSECInfo."""
        types = [dns.rdatatype.to_text(t) for t in rdata.windows]
        return NSECInfo(
            record_type="NSEC",
            next_domain=str(rdata.next),
            types_covered=types,
        )

    @staticmethod
    def parse_nsec3(rdata: NSEC3) -> NSECInfo:
        """Parse an NSEC3 record into NSECInfo."""
        types = [dns.rdatatype.to_text(t) for t in rdata.windows]
        return NSECInfo(
            record_type="NSEC3",
            next_domain=base64.b32encode(rdata.next).decode('ascii'),
            types_covered=types,
            hash_algorithm=rdata.algorithm,
            flags=rdata.flags,
            iterations=rdata.iterations,
            salt=rdata.salt.hex() if rdata.salt else "",
        )

    @staticmethod
    def parse_additional_record(
        name: str,
        record_type: str,
        rdata: dns.rdata.Rdata,
        ttl: int,
    ) -> AdditionalRecord:
        """Parse an additional record (SPF, DMARC, etc.)."""
        # Get string representation of the record
        value = str(rdata)

        # Clean up TXT record formatting
        if record_type in ("TXT", "SPF"):
            # Remove quotes from TXT records
            value = value.strip('"')

        return AdditionalRecord(
            record_type=record_type,
            name=name,
            value=value,
            ttl=ttl,
        )

    @staticmethod
    def format_key_tag(tag: int) -> str:
        """Format a key tag for display."""
        return f"{tag:05d}"

    @staticmethod
    def format_algorithm(algo: int) -> str:
        """Format an algorithm number with name."""
        name = ALGORITHM_NAMES.get(algo, "Unknown")
        return f"{algo} ({name})"

    @staticmethod
    def format_digest_type(dtype: int) -> str:
        """Format a digest type with name."""
        name = DIGEST_TYPE_NAMES.get(dtype, "Unknown")
        return f"{dtype} ({name})"

    @staticmethod
    def format_timestamp(dt: datetime) -> str:
        """Format a datetime for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    @staticmethod
    def format_ttl(ttl: int) -> str:
        """Format TTL in human-readable form."""
        if ttl < 60:
            return f"{ttl}s"
        if ttl < 3600:
            return f"{ttl // 60}m"
        if ttl < 86400:
            return f"{ttl // 3600}h"
        return f"{ttl // 86400}d"
