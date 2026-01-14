"""Data models for DNSSEC chain of trust."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ValidationStatus(Enum):
    """DNSSEC validation status."""
    SECURE = "secure"           # Fully validated chain
    INSECURE = "insecure"       # No DNSSEC (but not broken)
    BOGUS = "bogus"             # Validation failed
    INDETERMINATE = "indeterminate"  # Cannot determine
    UNKNOWN = "unknown"         # Not yet checked

    @property
    def color(self) -> str:
        """Return the Rich color for this status."""
        colors = {
            ValidationStatus.SECURE: "green",
            ValidationStatus.INSECURE: "yellow",
            ValidationStatus.BOGUS: "red",
            ValidationStatus.INDETERMINATE: "orange1",
            ValidationStatus.UNKNOWN: "dim",
        }
        return colors.get(self, "white")

    @property
    def symbol(self) -> str:
        """Return a symbol for this status."""
        symbols = {
            ValidationStatus.SECURE: "✓",
            ValidationStatus.INSECURE: "○",
            ValidationStatus.BOGUS: "✗",
            ValidationStatus.INDETERMINATE: "?",
            ValidationStatus.UNKNOWN: "·",
        }
        return symbols.get(self, "·")


@dataclass
class DNSKeyInfo:
    """Information about a DNSKEY record."""
    flags: int                  # 256 = ZSK, 257 = KSK
    protocol: int               # Should be 3
    algorithm: int              # Algorithm number
    algorithm_name: str         # Human-readable algorithm name
    key_tag: int                # Key tag (identifier)
    key_data: str               # Base64-encoded public key (truncated for display)
    key_length: int             # Key length in bits
    is_ksk: bool = field(init=False)
    is_zsk: bool = field(init=False)
    is_sep: bool = field(init=False)  # Secure Entry Point

    def __post_init__(self):
        self.is_ksk = (self.flags & 0x0001) == 1  # KSK has SEP bit set
        self.is_zsk = (self.flags & 0x0001) == 0  # ZSK does not have SEP bit
        self.is_sep = (self.flags & 0x0001) == 1

    @property
    def key_type(self) -> str:
        """Return human-readable key type."""
        if self.is_ksk:
            return "KSK"
        return "ZSK"

    @property
    def display_key(self) -> str:
        """Return truncated key for display."""
        if len(self.key_data) > 32:
            return f"{self.key_data[:16]}...{self.key_data[-16:]}"
        return self.key_data


@dataclass
class DSInfo:
    """Information about a DS (Delegation Signer) record."""
    key_tag: int                # References a DNSKEY
    algorithm: int              # Algorithm number
    algorithm_name: str         # Human-readable algorithm name
    digest_type: int            # Hash algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384)
    digest_type_name: str       # Human-readable digest type
    digest: str                 # The digest value (hex)
    validates_key: Optional[int] = None  # Key tag this validates (if verified)

    @property
    def display_digest(self) -> str:
        """Return truncated digest for display."""
        if len(self.digest) > 32:
            return f"{self.digest[:16]}...{self.digest[-16:]}"
        return self.digest


@dataclass
class RRSIGInfo:
    """Information about an RRSIG (signature) record."""
    type_covered: str           # Record type this signs (e.g., "DNSKEY", "A")
    algorithm: int              # Algorithm number
    algorithm_name: str         # Human-readable algorithm name
    labels: int                 # Number of labels in original name
    original_ttl: int           # Original TTL
    expiration: datetime        # Signature expiration
    inception: datetime         # Signature inception
    key_tag: int                # Key tag of signing key
    signer_name: str            # Name of the signer
    signature: str              # Base64-encoded signature
    is_valid: Optional[bool] = None  # Validation result
    validation_error: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        """Check if signature has expired."""
        return datetime.utcnow() > self.expiration

    @property
    def is_not_yet_valid(self) -> bool:
        """Check if signature is not yet valid."""
        return datetime.utcnow() < self.inception

    @property
    def days_until_expiry(self) -> int:
        """Return days until expiration (negative if expired)."""
        delta = self.expiration - datetime.utcnow()
        return delta.days

    @property
    def validity_status(self) -> str:
        """Return human-readable validity status."""
        if self.is_expired:
            return f"EXPIRED ({abs(self.days_until_expiry)} days ago)"
        if self.is_not_yet_valid:
            return "NOT YET VALID"
        if self.days_until_expiry < 7:
            return f"EXPIRING SOON ({self.days_until_expiry} days)"
        return f"Valid ({self.days_until_expiry} days)"


@dataclass
class NSECInfo:
    """Information about NSEC/NSEC3 records."""
    record_type: str            # "NSEC" or "NSEC3"
    next_domain: str            # Next domain name (or hash)
    types_covered: list[str]    # Record types at this name
    # NSEC3-specific fields
    hash_algorithm: Optional[int] = None
    flags: Optional[int] = None
    iterations: Optional[int] = None
    salt: Optional[str] = None


@dataclass
class AdditionalRecord:
    """Additional DNS records (SPF, DMARC, etc.)."""
    record_type: str            # "SPF", "DMARC", "DKIM", "MX", etc.
    name: str                   # Full record name
    value: str                  # Record value/content
    ttl: int                    # TTL
    is_signed: bool = False     # Whether this record is covered by RRSIG
    rrsig: Optional[RRSIGInfo] = None


@dataclass
class ServerResponse:
    """Response from a single authoritative nameserver."""
    server_ip: str              # IP address of the server
    server_name: str            # Hostname if known
    responded: bool = True      # Did the server respond?
    error: Optional[str] = None # Error message if failed
    response_time_ms: float = 0.0

    # Records received
    dnskey_tags: list[int] = field(default_factory=list)
    ds_tags: list[int] = field(default_factory=list)
    has_rrsig: bool = False


@dataclass
class ConsistencyResult:
    """Result of checking consistency across authoritative nameservers."""
    zone_name: str
    nameservers_queried: int = 0
    nameservers_responded: int = 0
    is_consistent: bool = True
    issues: list[str] = field(default_factory=list)
    server_responses: list[ServerResponse] = field(default_factory=list)

    @property
    def consistency_status(self) -> str:
        """Human-readable consistency status."""
        if not self.server_responses:
            return "Not checked"
        if self.nameservers_responded == 0:
            return "No responses"
        if self.is_consistent:
            return f"Consistent ({self.nameservers_responded}/{self.nameservers_queried})"
        return f"INCONSISTENT ({len(self.issues)} issues)"


@dataclass
class ZoneInfo:
    """Information about a single zone in the chain."""
    name: str                   # Zone name (e.g., "example.com.")
    parent: Optional[str] = None  # Parent zone name
    status: ValidationStatus = ValidationStatus.UNKNOWN
    status_reason: str = ""     # Explanation of status

    # DNSSEC records
    dnskeys: list[DNSKeyInfo] = field(default_factory=list)
    ds_records: list[DSInfo] = field(default_factory=list)
    rrsigs: list[RRSIGInfo] = field(default_factory=list)
    nsec_records: list[NSECInfo] = field(default_factory=list)

    # Validation details
    ds_validated: bool = False  # DS matches parent's delegation
    dnskey_validated: bool = False  # DNSKEY signed by valid key
    chain_complete: bool = False  # Full chain to this zone validates

    # Additional records (only for target zone)
    additional_records: list[AdditionalRecord] = field(default_factory=list)

    # Consistency check results
    consistency: Optional[ConsistencyResult] = None

    @property
    def has_dnssec(self) -> bool:
        """Check if zone has DNSSEC."""
        return len(self.dnskeys) > 0

    @property
    def ksk_count(self) -> int:
        """Count KSK keys."""
        return sum(1 for k in self.dnskeys if k.is_ksk)

    @property
    def zsk_count(self) -> int:
        """Count ZSK keys."""
        return sum(1 for k in self.dnskeys if k.is_zsk)

    def get_key_by_tag(self, tag: int) -> Optional[DNSKeyInfo]:
        """Find a DNSKEY by its key tag."""
        for key in self.dnskeys:
            if key.key_tag == tag:
                return key
        return None


@dataclass
class TrustChain:
    """Complete chain of trust from root to target domain."""
    target_domain: str          # The queried domain
    query_time: datetime = field(default_factory=datetime.utcnow)
    zones: list[ZoneInfo] = field(default_factory=list)
    overall_status: ValidationStatus = ValidationStatus.UNKNOWN
    overall_reason: str = ""

    # Resolver info
    resolver_used: str = ""
    query_duration_ms: float = 0.0

    @property
    def is_secure(self) -> bool:
        """Check if the entire chain is secure."""
        return self.overall_status == ValidationStatus.SECURE

    @property
    def zone_count(self) -> int:
        """Number of zones in the chain."""
        return len(self.zones)

    def get_zone(self, name: str) -> Optional[ZoneInfo]:
        """Get a zone by name."""
        for zone in self.zones:
            if zone.name == name:
                return zone
        return None

    @property
    def root_zone(self) -> Optional[ZoneInfo]:
        """Get the root zone."""
        return self.get_zone(".")

    @property
    def target_zone(self) -> Optional[ZoneInfo]:
        """Get the target domain's zone."""
        if self.zones:
            return self.zones[-1]
        return None

    def chain_path(self) -> list[str]:
        """Return the zone names in order from root to target."""
        return [z.name for z in self.zones]
