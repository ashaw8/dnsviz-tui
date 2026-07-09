"""Diagram view: dnsviz.net-style DNSSEC authentication chain graph."""

from rich.console import RenderableType, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from dnsviz_tui.models.chain import TrustChain
from dnsviz_tui.views.graph import build_diagram


class DiagramView(Static):
    """Graph visualization of the DNSSEC chain of trust, one box per zone
    with individual DNSKEY/DS nodes and signing edges between them."""

    DEFAULT_CSS = """
    DiagramView {
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

    def _build_header(self) -> Table:
        header = Table.grid(padding=(0, 2))
        header.add_column()
        header.add_column()
        header.add_column()

        status = self._chain.overall_status
        status_text = Text()
        status_text.append(f"{status.symbol} ", style=f"bold {status.color}")
        status_text.append(status.value.upper(), style=f"bold {status.color}")

        header.add_row(
            Text(f"Domain: {self._chain.target_domain}", style="bold"),
            status_text,
            Text(f"Query: {self._chain.query_duration_ms:.0f}ms", style="dim"),
        )
        return header

    def _build_legend(self) -> Text:
        legend = Text(style="dim")
        legend.append("grey fill", style="on grey30")
        legend.append(" KSK (SEP)   ")
        legend.append("╔═╗", style="bold #1f9e9e")
        legend.append(" trust anchor   ")
        legend.append("◀╮", style="#1f9e9e")
        legend.append(" signs own RRset   arrows follow the signing chain")
        return legend

    def render(self) -> RenderableType:
        if not self._chain:
            return Panel(
                Text("Enter a domain to analyze", style="dim"),
                title="Chain of Trust - Diagram View",
                border_style="dim",
            )

        # Fit the graph to the widget; fall back before first layout pass.
        width = self.size.width if self.size.width > 20 else 104
        graph = build_diagram(self._chain, max_width=max(60, width - 8))

        content = Group(
            self._build_header(),
            Text(""),
            graph,
            self._build_legend(),
        )

        return Panel(
            content,
            title="[bold]Chain of Trust - Diagram View[/bold]",
            subtitle=f"[dim]{self._chain.overall_reason}[/dim]",
            border_style=self._chain.overall_status.color,
            padding=(1, 2),
        )
