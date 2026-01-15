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
    ConsistencyResult,
    ServerResponse,
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
        """Query additional records for a domain (SOA, NS, SPF, DMARC, etc.).

        Args:
            domain: Domain name

        Returns:
            List of AdditionalRecord objects
        """
        records = []

        # Normalize domain
        if not domain.endswith('.'):
            domain = domain + '.'

        # Query SOA record first (zone authority info)
        try:
            soa_answer = self._query(domain, "SOA")
            if soa_answer:
                has_rrsig = False
                rrsig_info = None
                if soa_answer.response:
                    for rrset in soa_answer.response.answer:
                        if rrset.rdtype == dns.rdatatype.RRSIG:
                            for rdata in rrset:
                                if isinstance(rdata, RRSIG):
                                    has_rrsig = True
                                    rrsig_info = self._formatter.parse_rrsig(rdata)
                                    break

                for rdata in soa_answer:
                    # Format SOA with serial first (most important), then other fields
                    # Shorten mname/rname to fit better
                    mname = str(rdata.mname).rstrip('.')
                    rname = str(rdata.rname).rstrip('.')
                    if len(mname) > 25:
                        mname = mname[:22] + "..."
                    if len(rname) > 25:
                        rname = rname[:22] + "..."
                    soa_value = (
                        f"serial={rdata.serial} "
                        f"primary={mname} "
                        f"admin={rname} "
                        f"refresh={rdata.refresh} "
                        f"retry={rdata.retry} "
                        f"expire={rdata.expire} "
                        f"min={rdata.minimum}"
                    )
                    records.append(AdditionalRecord(
                        record_type="SOA",
                        name=domain,
                        value=soa_value,
                        ttl=soa_answer.rrset.ttl if soa_answer.rrset else 0,
                        is_signed=has_rrsig,
                        rrsig=rrsig_info,
                    ))
        except Exception:
            pass

        # Query NS records (nameservers)
        try:
            ns_answer = self._query(domain, "NS")
            if ns_answer:
                has_rrsig = False
                rrsig_info = None
                if ns_answer.response:
                    for rrset in ns_answer.response.answer:
                        if rrset.rdtype == dns.rdatatype.RRSIG:
                            for rdata in rrset:
                                if isinstance(rdata, RRSIG):
                                    has_rrsig = True
                                    rrsig_info = self._formatter.parse_rrsig(rdata)
                                    break

                for rdata in ns_answer:
                    ns_name = str(rdata.target)
                    # Try to resolve NS to IP for display
                    ns_ip = ""
                    try:
                        a_answer = self._query(ns_name, "A")
                        if a_answer:
                            ns_ip = f" ({', '.join(str(r) for r in a_answer)})"
                    except Exception:
                        pass

                    records.append(AdditionalRecord(
                        record_type="NS",
                        name=domain,
                        value=f"{ns_name}{ns_ip}",
                        ttl=ns_answer.rrset.ttl if ns_answer.rrset else 0,
                        is_signed=has_rrsig,
                        rrsig=rrsig_info,
                    ))
        except Exception:
            pass

        # Query other common record types
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

    def query_zone_chain(
        self,
        domain: str,
        check_consistency: bool = True
    ) -> tuple[list[ZoneInfo], float]:
        """Query the complete DNSSEC chain for a domain.

        Args:
            domain: Target domain
            check_consistency: Whether to check consistency across nameservers

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

            # Perform consistency check (skip root zone - too many servers)
            if check_consistency and zone_name != ".":
                zone_info.consistency = self.check_consistency(zone_name)

            zones.append(zone_info)

        query_time = (time.time() - start_time) * 1000
        return zones, query_time

    def get_authoritative_nameservers(self, zone: str) -> list[tuple[str, str]]:
        """Get authoritative nameservers for a zone.

        Args:
            zone: Zone name (e.g., "example.com.")

        Returns:
            List of (hostname, ip_address) tuples
        """
        nameservers = []

        try:
            # Query NS records
            ns_answer = self._query(zone, "NS")
            if not ns_answer:
                return []

            for rdata in ns_answer:
                ns_name = str(rdata.target)

                # Resolve NS to IP
                try:
                    a_answer = self._query(ns_name, "A")
                    if a_answer:
                        for a_rdata in a_answer:
                            nameservers.append((ns_name, str(a_rdata)))
                except Exception:
                    pass

        except Exception:
            pass

        return nameservers

    def query_nameserver_direct(
        self,
        nameserver_ip: str,
        zone: str,
        timeout: float = 3.0
    ) -> ServerResponse:
        """Query a specific nameserver directly for DNSKEY records.

        Args:
            nameserver_ip: IP address of the nameserver
            zone: Zone to query
            timeout: Query timeout in seconds

        Returns:
            ServerResponse with results
        """
        response = ServerResponse(
            server_ip=nameserver_ip,
            server_name="",
            responded=False
        )

        try:
            start_time = time.time()

            # Build DNSKEY query with DO bit
            query = dns.message.make_query(
                zone,
                dns.rdatatype.DNSKEY,
                want_dnssec=True
            )

            # Query the specific nameserver
            answer = dns.query.udp(
                query,
                nameserver_ip,
                timeout=timeout
            )

            response.response_time_ms = (time.time() - start_time) * 1000
            response.responded = True

            # Extract DNSKEY key tags
            for rrset in answer.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    for rdata in rrset:
                        if isinstance(rdata, DNSKEY):
                            key_info = self._formatter.parse_dnskey(rdata)
                            response.dnskey_tags.append(key_info.key_tag)
                elif rrset.rdtype == dns.rdatatype.RRSIG:
                    response.has_rrsig = True

        except dns.exception.Timeout:
            response.error = "Timeout"
        except Exception as e:
            response.error = str(e)

        return response

    def check_consistency(
        self,
        zone: str,
        max_servers: int = 5
    ) -> ConsistencyResult:
        """Check DNSKEY consistency across authoritative nameservers.

        Args:
            zone: Zone to check
            max_servers: Maximum number of servers to query

        Returns:
            ConsistencyResult with findings
        """
        result = ConsistencyResult(zone_name=zone)

        # Get authoritative nameservers
        nameservers = self.get_authoritative_nameservers(zone)
        if not nameservers:
            result.issues.append("Could not find authoritative nameservers")
            return result

        # Limit the number of servers to query
        nameservers = nameservers[:max_servers]
        result.nameservers_queried = len(nameservers)

        # Query each nameserver
        all_key_sets = []

        for ns_name, ns_ip in nameservers:
            response = self.query_nameserver_direct(ns_ip, zone)
            response.server_name = ns_name
            result.server_responses.append(response)

            if response.responded:
                result.nameservers_responded += 1
                all_key_sets.append(set(response.dnskey_tags))

        # Check for consistency
        if len(all_key_sets) > 1:
            # Compare all key sets
            reference_set = all_key_sets[0]
            for i, key_set in enumerate(all_key_sets[1:], 1):
                if key_set != reference_set:
                    result.is_consistent = False
                    missing = reference_set - key_set
                    extra = key_set - reference_set
                    server = result.server_responses[i]
                    if missing:
                        result.issues.append(
                            f"{server.server_name} missing keys: {missing}"
                        )
                    if extra:
                        result.issues.append(
                            f"{server.server_name} has extra keys: {extra}"
                        )

        # Check for servers that didn't respond
        non_responsive = [
            r for r in result.server_responses if not r.responded
        ]
        if non_responsive:
            for r in non_responsive:
                result.issues.append(
                    f"{r.server_ip} did not respond: {r.error or 'unknown'}"
                )

        # Check for servers without RRSIG (unsigned responses)
        for r in result.server_responses:
            if r.responded and not r.has_rrsig and r.dnskey_tags:
                result.issues.append(
                    f"{r.server_name} returned DNSKEY without RRSIG"
                )
                result.is_consistent = False

        return result
