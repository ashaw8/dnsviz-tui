"""ASCII diagram view visualization for DNSSEC chain of trust."""

from rich.console import RenderableType, Console, Group
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from textual.widgets import Static

from dnsviz_tui.models.chain import (
    TrustChain,
    ZoneInfo,
    ValidationStatus,
)


class DiagramView(Static):
    """ASCII box diagram visualization of DNSSEC chain of trust."""

    DEFAULT_CSS = """
    DiagramView {
        height: auto;
        padding: 1;
    }
    """

    # Box drawing characters
    BOX_TL = "┌"
    BOX_TR = "┐"
    BOX_BL = "└"
    BOX_BR = "┘"
    BOX_H = "─"
    BOX_V = "│"
    ARROW_R = "─▶"
    ARROW_D = "▼"
    LINK_H = "═══"
    LINK_LABEL = "DS"

    def __init__(self, chain: TrustChain | None = None, **kwargs):
        super().__init__(**kwargs)
        self._chain = chain

    def set_chain(self, chain: TrustChain) -> None:
        """Set the trust chain to display."""
        self._chain = chain
        self.refresh()

    def _create_zone_box(self, zone: ZoneInfo, width: int = 24) -> Text:
        """Create an ASCII box for a zone."""
        lines = []
        status = zone.status
        color = status.color

        # Zone name (centered)
        name = zone.name if zone.name != "." else ". (root)"
        if len(name) > width - 4:
            name = name[:width - 7] + "..."

        # Top border
        top = f"{self.BOX_TL}{self.BOX_H * (width - 2)}{self.BOX_TR}"
        lines.append(Text(top, style=color))

        # Zone name row
        name_padded = name.center(width - 4)
        name_row = Text()
        name_row.append(self.BOX_V, style=color)
        name_row.append(" ")
        name_row.append(name_padded, style="bold white")
        name_row.append(" ")
        name_row.append(self.BOX_V, style=color)
        lines.append(name_row)

        # Separator
        sep = f"{self.BOX_V}{self.BOX_H * (width - 2)}{self.BOX_V}"
        lines.append(Text(sep, style=color))

        # Status row
        status_text = f"{status.symbol} {status.value.upper()}"
        status_padded = status_text.center(width - 4)
        status_row = Text()
        status_row.append(self.BOX_V, style=color)
        status_row.append(" ")
        status_row.append(status_padded, style=f"bold {color}")
        status_row.append(" ")
        status_row.append(self.BOX_V, style=color)
        lines.append(status_row)

        # Key info rows
        if zone.dnskeys:
            ksk_count = sum(1 for k in zone.dnskeys if k.is_ksk)
            zsk_count = sum(1 for k in zone.dnskeys if k.is_zsk)
            key_info = f"KSK:{ksk_count} ZSK:{zsk_count}"
            key_padded = key_info.center(width - 4)
            key_row = Text()
            key_row.append(self.BOX_V, style=color)
            key_row.append(" ")
            key_row.append(key_padded, style="cyan")
            key_row.append(" ")
            key_row.append(self.BOX_V, style=color)
            lines.append(key_row)

            # Show key tags
            tags = [str(k.key_tag) for k in zone.dnskeys[:3]]
            if len(zone.dnskeys) > 3:
                tags.append("...")
            tags_str = ",".join(tags)
            if len(tags_str) > width - 6:
                tags_str = tags_str[:width - 9] + "..."
            tags_padded = tags_str.center(width - 4)
            tags_row = Text()
            tags_row.append(self.BOX_V, style=color)
            tags_row.append(" ")
            tags_row.append(tags_padded, style="dim cyan")
            tags_row.append(" ")
            tags_row.append(self.BOX_V, style=color)
            lines.append(tags_row)
        else:
            # No DNSSEC
            no_dnssec = "No DNSKEY".center(width - 4)
            no_row = Text()
            no_row.append(self.BOX_V, style=color)
            no_row.append(" ")
            no_row.append(no_dnssec, style="dim")
            no_row.append(" ")
            no_row.append(self.BOX_V, style=color)
            lines.append(no_row)

        # Bottom border
        bottom = f"{self.BOX_BL}{self.BOX_H * (width - 2)}{self.BOX_BR}"
        lines.append(Text(bottom, style=color))

        # Combine lines
        result = Text()
        for i, line in enumerate(lines):
            result.append_text(line)
            if i < len(lines) - 1:
                result.append("\n")

        return result

    def _create_arrow(self, ds_records: list, validated: bool) -> Text:
        """Create an arrow with DS label showing the delegation."""
        lines = []
        color = "green" if validated else "yellow"

        # Arrow line with DS label
        if ds_records:
            ds_tags = [str(ds.key_tag) for ds in ds_records[:2]]
            if len(ds_records) > 2:
                ds_tags.append("...")
            label = f"DS:{','.join(ds_tags)}"
        else:
            label = "No DS"
            color = "red" if validated else "dim"

        # Create arrow: ══DS══▶
        arrow = Text()
        arrow.append("══", style=color)
        arrow.append(label, style=f"bold {color}")
        arrow.append("══▶", style=color)

        return arrow

    def _build_horizontal_chain(self) -> RenderableType:
        """Build horizontal chain diagram (for few zones)."""
        if not self._chain or not self._chain.zones:
            return Text("No data")

        zones = self._chain.zones
        box_width = 22

        # Build zone boxes
        elements = []
        for i, zone in enumerate(zones):
            # Add zone box
            box = self._create_zone_box(zone, box_width)
            elements.append(Panel(box, border_style="dim", padding=0))

            # Add arrow (except after last zone)
            if i < len(zones) - 1:
                next_zone = zones[i + 1]
                arrow = self._create_arrow(
                    next_zone.ds_records,
                    next_zone.ds_validated
                )
                # Wrap arrow for vertical centering
                arrow_panel = Text("\n\n")
                arrow_panel.append_text(arrow)
                elements.append(arrow_panel)

        return Columns(elements, padding=0, expand=False)

    def _build_vertical_chain(self) -> RenderableType:
        """Build vertical chain diagram (for many zones)."""
        if not self._chain or not self._chain.zones:
            return Text("No data")

        zones = self._chain.zones
        box_width = 32
        content = []

        for i, zone in enumerate(zones):
            # Add zone box
            box = self._create_zone_box(zone, box_width)
            content.append(box)

            # Add arrow (except after last zone)
            if i < len(zones) - 1:
                next_zone = zones[i + 1]

                # Vertical arrow with DS info
                arrow_text = Text()
                color = "green" if next_zone.ds_validated else "yellow"

                if next_zone.ds_records:
                    ds_tags = [str(ds.key_tag) for ds in next_zone.ds_records[:2]]
                    label = f"DS: {', '.join(ds_tags)}"
                else:
                    label = "No DS"
                    color = "dim"

                # Create vertical connector
                arrow_text.append("        │\n", style=color)
                arrow_text.append(f"        │ {label}\n", style=color)
                arrow_text.append("        ▼\n", style=color)

                content.append(arrow_text)

        return Group(*content)

    def _build_summary_table(self) -> Table:
        """Build a summary table of the chain."""
        table = Table(
            title=None,
            show_header=True,
            header_style="bold",
            border_style="dim",
            padding=(0, 1),
        )

        table.add_column("Zone", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Keys", justify="center")
        table.add_column("DS→DNSKEY", justify="center")
        table.add_column("Signatures", justify="center")

        for zone in self._chain.zones:
            # Status
            status = Text(f"{zone.status.symbol} {zone.status.value}", style=zone.status.color)

            # Keys
            if zone.dnskeys:
                ksk = sum(1 for k in zone.dnskeys if k.is_ksk)
                zsk = sum(1 for k in zone.dnskeys if k.is_zsk)
                keys = Text(f"{ksk}K/{zsk}Z", style="cyan")
            else:
                keys = Text("-", style="dim")

            # DS validation
            if zone.name == ".":
                ds_val = Text("Trust Anchor", style="magenta")
            elif zone.ds_validated:
                ds_val = Text("✓ Validated", style="green")
            elif zone.ds_records:
                ds_val = Text("✗ Failed", style="red")
            else:
                ds_val = Text("-", style="dim")

            # Signatures
            if zone.rrsigs:
                valid_count = sum(1 for r in zone.rrsigs if r.is_valid)
                total = len(zone.rrsigs)
                if valid_count == total:
                    sigs = Text(f"✓ {total}", style="green")
                else:
                    sigs = Text(f"{valid_count}/{total}", style="yellow")
            else:
                sigs = Text("-", style="dim")

            table.add_row(
                zone.name if zone.name != "." else ". (root)",
                status,
                keys,
                ds_val,
                sigs,
            )

        return table

    def render(self) -> RenderableType:
        """Render the diagram view."""
        if not self._chain:
            return Panel(
                Text("Enter a domain to analyze", style="dim"),
                title="Chain of Trust - Diagram View",
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

        # Choose layout based on number of zones
        if len(self._chain.zones) <= 4:
            chain_viz = self._build_horizontal_chain()
        else:
            chain_viz = self._build_vertical_chain()

        # Build summary table
        summary = self._build_summary_table()

        # Combine all elements
        content = Group(
            header,
            Text(""),
            Text("Trust Chain Flow:", style="bold underline"),
            Text(""),
            chain_viz,
            Text(""),
            Text("Chain Summary:", style="bold underline"),
            Text(""),
            summary,
        )

        return Panel(
            content,
            title="[bold]Chain of Trust - Diagram View[/bold]",
            subtitle=f"[dim]{self._chain.overall_reason}[/dim]",
            border_style=self._chain.overall_status.color,
            padding=(1, 2),
        )
