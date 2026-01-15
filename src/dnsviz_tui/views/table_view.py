"""Table view visualization for DNSSEC chain of trust."""

from rich.console import RenderableType, Group
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from textual.widgets import Static

from dnsviz_tui.models.chain import (
    TrustChain,
    ZoneInfo,
    ValidationStatus,
)


class TableView(Static):
    """Table visualization of DNSSEC chain of trust."""

    DEFAULT_CSS = """
    TableView {
        height: auto;
        padding: 1;
    }
    """

    def __init__(self, chain: TrustChain | None = None, **kwargs):
        super().__init__(**kwargs)
        self._chain = chain

    def set_chain(self, chain: TrustChain) -> None:
        """Set the trust chain to display."""
        self._chain = chain
        self.refresh()

    def _build_dnskey_table(self) -> Table:
        """Build table of all DNSKEY records."""
        table = Table(
            title="[bold]DNSKEY Records[/bold]",
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Zone", style="bold")
        table.add_column("Type", justify="center")
        table.add_column("Key Tag", justify="right", style="cyan")
        table.add_column("Algorithm", style="yellow")
        table.add_column("Bits", justify="right")
        table.add_column("Flags", justify="right", style="dim")
        table.add_column("Key (truncated)", style="dim", max_width=24)

        for zone in self._chain.zones:
            for key in zone.dnskeys:
                key_type = Text("KSK", style="bold magenta") if key.is_ksk else Text("ZSK", style="bold blue")

                table.add_row(
                    zone.name,
                    key_type,
                    str(key.key_tag),
                    key.algorithm_name,
                    str(key.key_length),
                    str(key.flags),
                    key.display_key,
                )

        return table

    def _build_ds_table(self) -> Table:
        """Build table of all DS records."""
        table = Table(
            title="[bold]DS Records (Delegation Signer)[/bold]",
            show_header=True,
            header_style="bold green",
            border_style="green",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Zone", style="bold")
        table.add_column("Key Tag", justify="right", style="cyan")
        table.add_column("Algorithm", style="yellow")
        table.add_column("Digest Type")
        table.add_column("Digest (truncated)", style="dim", max_width=32)
        table.add_column("Validates", justify="center")

        for zone in self._chain.zones:
            for ds in zone.ds_records:
                validates = ""
                if ds.validates_key:
                    validates = Text(f"✓ {ds.validates_key}", style="green")
                else:
                    validates = Text("-", style="dim")

                table.add_row(
                    zone.name,
                    str(ds.key_tag),
                    ds.algorithm_name,
                    ds.digest_type_name,
                    ds.display_digest,
                    validates,
                )

        return table

    def _build_rrsig_table(self) -> Table:
        """Build table of all RRSIG records."""
        table = Table(
            title="[bold]RRSIG Records (Signatures)[/bold]",
            show_header=True,
            header_style="bold orange1",
            border_style="orange1",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Zone", style="bold")
        table.add_column("Covers", style="cyan")
        table.add_column("Key Tag", justify="right")
        table.add_column("Algorithm", style="yellow")
        table.add_column("Expiration")
        table.add_column("Status", justify="center")

        for zone in self._chain.zones:
            for rrsig in zone.rrsigs:
                # Determine status and color
                if rrsig.is_expired:
                    status = Text("EXPIRED", style="bold red")
                    exp_style = "red"
                elif rrsig.is_not_yet_valid:
                    status = Text("NOT VALID", style="bold yellow")
                    exp_style = "yellow"
                elif rrsig.days_until_expiry < 7:
                    status = Text(f"{rrsig.days_until_expiry}d left", style="yellow")
                    exp_style = "yellow"
                else:
                    status = Text("✓ Valid", style="green")
                    exp_style = "green"

                exp_text = Text(
                    rrsig.expiration.strftime("%Y-%m-%d"),
                    style=exp_style
                )

                table.add_row(
                    zone.name,
                    rrsig.type_covered,
                    str(rrsig.key_tag),
                    rrsig.algorithm_name,
                    exp_text,
                    status,
                )

        return table

    def _build_zone_status_table(self) -> Table:
        """Build table showing zone validation status."""
        table = Table(
            title="[bold]Zone Validation Status[/bold]",
            show_header=True,
            header_style="bold white",
            border_style="white",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Zone", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("DS Valid", justify="center")
        table.add_column("DNSKEY Valid", justify="center")
        table.add_column("Chain OK", justify="center")
        table.add_column("Reason")

        for zone in self._chain.zones:
            status = Text(
                f"{zone.status.symbol} {zone.status.value.upper()}",
                style=f"bold {zone.status.color}"
            )

            ds_valid = Text("✓", style="green") if zone.ds_validated else Text("-", style="dim")
            dnskey_valid = Text("✓", style="green") if zone.dnskey_validated else Text("-", style="dim")
            chain_ok = Text("✓", style="green") if zone.chain_complete else Text("-", style="dim")

            # For root, DS validation is trust anchor
            if zone.name == ".":
                ds_valid = Text("⚓", style="magenta")  # Anchor symbol

            reason = zone.status_reason if zone.status_reason else "-"
            if len(reason) > 40:
                reason = reason[:37] + "..."

            table.add_row(
                zone.name,
                status,
                ds_valid,
                dnskey_valid,
                chain_ok,
                reason,
            )

        return table

    def _build_consistency_table(self) -> Table | None:
        """Build table showing consistency check results across nameservers."""
        # Check if any zone has consistency data
        has_consistency = any(
            zone.consistency is not None for zone in self._chain.zones
        )
        if not has_consistency:
            return None

        table = Table(
            title="[bold]Nameserver Consistency Check[/bold]",
            show_header=True,
            header_style="bold magenta",
            border_style="magenta",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Zone", style="bold")
        table.add_column("Servers", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Issues")

        for zone in self._chain.zones:
            if not zone.consistency:
                continue

            c = zone.consistency

            # Server count
            servers = f"{c.nameservers_responded}/{c.nameservers_queried}"

            # Status
            if c.is_consistent and c.nameservers_responded > 0:
                status = Text("✓ Consistent", style="green")
            elif c.nameservers_responded == 0:
                status = Text("No response", style="red")
            else:
                status = Text("✗ Inconsistent", style="red")

            # Issues
            if c.issues:
                issues_text = "; ".join(c.issues[:2])
                if len(c.issues) > 2:
                    issues_text += f" (+{len(c.issues) - 2} more)"
                if len(issues_text) > 50:
                    issues_text = issues_text[:47] + "..."
            else:
                issues_text = "-"

            table.add_row(
                zone.name,
                servers,
                status,
                issues_text,
            )

        return table

    def _build_additional_records_table(self) -> Table | None:
        """Build table of additional records (SPF, DMARC, etc.)."""
        # Collect all additional records
        all_records = []
        for zone in self._chain.zones:
            all_records.extend(zone.additional_records)

        if not all_records:
            return None

        table = Table(
            title="[bold]Additional Records[/bold]",
            show_header=True,
            header_style="bold blue",
            border_style="blue",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Type", style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Value")
        table.add_column("TTL", justify="right", style="dim")
        table.add_column("Signed", justify="center")

        for record in all_records:
            signed = Text("✓", style="green") if record.is_signed else Text("-", style="dim")

            value = record.value
            # SOA records need more space to show serial
            max_len = 90 if record.record_type == "SOA" else 60
            if len(value) > max_len:
                value = value[:max_len - 3] + "..."

            table.add_row(
                record.record_type,
                record.name,
                value,
                str(record.ttl),
                signed,
            )

        return table

    def render(self) -> RenderableType:
        """Render the table view."""
        if not self._chain:
            return Panel(
                Text("Enter a domain to analyze", style="dim"),
                title="Chain of Trust - Table View",
                border_style="dim",
            )

        # Create header
        header = Table.grid(padding=(0, 2))
        header.add_column()
        header.add_column()
        header.add_column()

        status_text = Text()
        status_text.append(f"{self._chain.overall_status.symbol} ", style=f"bold {self._chain.overall_status.color}")
        status_text.append(self._chain.overall_status.value.upper(), style=f"bold {self._chain.overall_status.color}")

        header.add_row(
            Text(f"Domain: {self._chain.target_domain}", style="bold"),
            status_text,
            Text(f"Query: {self._chain.query_duration_ms:.0f}ms", style="dim"),
        )

        # Build all tables
        tables = [
            header,
            Text(""),
            self._build_zone_status_table(),
            Text(""),
            self._build_dnskey_table(),
            Text(""),
            self._build_ds_table(),
            Text(""),
            self._build_rrsig_table(),
        ]

        # Add consistency table if present
        consistency = self._build_consistency_table()
        if consistency:
            tables.extend([Text(""), consistency])

        # Add additional records if present
        additional = self._build_additional_records_table()
        if additional:
            tables.extend([Text(""), additional])

        content = Group(*tables)

        return Panel(
            content,
            title="[bold]Chain of Trust - Table View[/bold]",
            subtitle=f"[dim]{self._chain.overall_reason}[/dim]",
            border_style=self._chain.overall_status.color,
            padding=(1, 2),
        )
