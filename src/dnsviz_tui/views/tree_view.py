"""Tree view visualization for DNSSEC chain of trust."""

from rich.console import RenderableType
from rich.text import Text
from rich.tree import Tree
from rich.panel import Panel
from rich.table import Table
from textual.widgets import Static

from dnsviz_tui.models.chain import (
    TrustChain,
    ZoneInfo,
    ValidationStatus,
    DNSKeyInfo,
    DSInfo,
    RRSIGInfo,
)


class TreeView(Static):
    """Tree visualization of DNSSEC chain of trust."""

    DEFAULT_CSS = """
    TreeView {
        height: 100%;
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

    def _status_badge(self, status: ValidationStatus) -> Text:
        """Create a colored status badge."""
        return Text(f" {status.symbol} {status.value.upper()} ", style=f"bold {status.color} on {status.color}20")

    def _format_key_info(self, key: DNSKeyInfo) -> Text:
        """Format a DNSKEY for display."""
        text = Text()

        # Key type badge
        if key.is_ksk:
            text.append("KSK", style="bold magenta")
        else:
            text.append("ZSK", style="bold blue")

        text.append(" ")

        # Key tag
        text.append(f"tag={key.key_tag}", style="cyan")
        text.append(" | ")

        # Algorithm
        text.append(f"{key.algorithm_name}", style="yellow")
        text.append(" | ")

        # Key length
        text.append(f"{key.key_length}-bit", style="dim")

        return text

    def _format_ds_info(self, ds: DSInfo) -> Text:
        """Format a DS record for display."""
        text = Text()
        text.append("DS", style="bold green")
        text.append(" ")
        text.append(f"tag={ds.key_tag}", style="cyan")
        text.append(" | ")
        text.append(f"{ds.algorithm_name}", style="yellow")
        text.append(" | ")
        text.append(f"{ds.digest_type_name}", style="dim")

        if ds.validates_key:
            text.append(" ")
            text.append(f"→ validates DNSKEY {ds.validates_key}", style="green")

        return text

    def _format_rrsig_info(self, rrsig: RRSIGInfo) -> Text:
        """Format an RRSIG for display."""
        text = Text()
        text.append("RRSIG", style="bold orange1")
        text.append(" ")
        text.append(f"{rrsig.type_covered}", style="cyan")
        text.append(" | ")
        text.append(f"key={rrsig.key_tag}", style="dim cyan")
        text.append(" | ")

        # Validity status with color
        if rrsig.is_expired:
            text.append(f"EXPIRED", style="bold red")
        elif rrsig.is_not_yet_valid:
            text.append("NOT YET VALID", style="bold yellow")
        elif rrsig.days_until_expiry < 7:
            text.append(f"expires in {rrsig.days_until_expiry}d", style="yellow")
        else:
            text.append(f"valid {rrsig.days_until_expiry}d", style="green")

        return text

    def _build_zone_branch(self, tree: Tree, zone: ZoneInfo) -> Tree:
        """Build a tree branch for a zone."""
        # Zone header with status
        zone_label = Text()
        zone_label.append(f"{zone.name}", style="bold white")
        zone_label.append(" ")
        zone_label.append(f"[{zone.status.symbol} {zone.status.value.upper()}]", style=zone.status.color)

        branch = tree.add(zone_label)

        # Status reason if not secure
        if zone.status_reason and zone.status != ValidationStatus.SECURE:
            branch.add(Text(f"⚠ {zone.status_reason}", style="dim yellow"))

        # DNSKEY records
        if zone.dnskeys:
            keys_branch = branch.add(Text("🔑 DNSKEY Records", style="bold"))
            for key in zone.dnskeys:
                keys_branch.add(self._format_key_info(key))

        # DS records
        if zone.ds_records:
            ds_branch = branch.add(Text("🔗 DS Records (from parent)", style="bold"))
            for ds in zone.ds_records:
                ds_branch.add(self._format_ds_info(ds))

        # RRSIG records
        if zone.rrsigs:
            sig_branch = branch.add(Text("✍ Signatures (RRSIG)", style="bold"))
            for rrsig in zone.rrsigs:
                sig_branch.add(self._format_rrsig_info(rrsig))

        # Additional records (for target zone)
        if zone.additional_records:
            add_branch = branch.add(Text("📋 Additional Records", style="bold"))
            for record in zone.additional_records:
                rec_text = Text()
                rec_text.append(f"{record.record_type}", style="cyan")
                rec_text.append(": ")
                # Truncate long values
                value = record.value
                if len(value) > 60:
                    value = value[:57] + "..."
                rec_text.append(value, style="dim")
                if record.is_signed:
                    rec_text.append(" ✓", style="green")
                add_branch.add(rec_text)

        return branch

    def render(self) -> RenderableType:
        """Render the tree view."""
        if not self._chain:
            return Panel(
                Text("Enter a domain to analyze", style="dim"),
                title="Chain of Trust - Tree View",
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

        # Build the tree
        tree = Tree(
            Text("🌐 Chain of Trust", style="bold white"),
            guide_style="dim",
        )

        # Add zones
        for zone in self._chain.zones:
            self._build_zone_branch(tree, zone)

        # Create panel with tree
        from rich.console import Group
        content = Group(header, Text(""), tree)

        return Panel(
            content,
            title="[bold]Chain of Trust - Tree View[/bold]",
            subtitle=f"[dim]{self._chain.overall_reason}[/dim]",
            border_style=self._chain.overall_status.color,
            padding=(1, 2),
        )
