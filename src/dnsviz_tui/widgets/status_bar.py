"""Status bar widget."""

from textual.widgets import Static
from rich.text import Text
from rich.table import Table

from dnsviz_tui.models.chain import TrustChain, ValidationStatus


class StatusBar(Static):
    """Status bar showing current state and keybindings."""

    DEFAULT_CSS = """
    StatusBar {
        dock: bottom;
        height: 3;
        background: $surface;
        border-top: solid $primary;
        padding: 0 2;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._chain: TrustChain | None = None
        self._view_mode: str = "tree"
        self._resolver: str = "default"
        self._loading: bool = False

    def set_chain(self, chain: TrustChain | None) -> None:
        """Set the current chain."""
        self._chain = chain
        self.refresh()

    def set_view_mode(self, mode: str) -> None:
        """Set the current view mode."""
        self._view_mode = mode
        self.refresh()

    def set_resolver(self, resolver: str) -> None:
        """Set the resolver info."""
        self._resolver = resolver
        self.refresh()

    def set_loading(self, loading: bool) -> None:
        """Set loading state."""
        self._loading = loading
        self.refresh()

    def render(self) -> Table:
        """Render the status bar."""
        table = Table.grid(expand=True)
        table.add_column(ratio=1)  # Left: status
        table.add_column(ratio=2)  # Center: keybindings
        table.add_column(ratio=1, justify="right")  # Right: view mode

        # Left: Current status
        left = Text()
        if self._loading:
            left.append("⏳ Loading...", style="yellow")
        elif self._chain:
            status = self._chain.overall_status
            left.append(f"{status.symbol} ", style=status.color)
            left.append(self._chain.target_domain, style="bold")
        else:
            left.append("Ready", style="dim")

        # Center: Keybindings
        center = Text()
        bindings = [
            ("Enter", "Query"),
            ("1/2/3", "View"),
            ("e", "Export"),
            ("r", "Resolver"),
            ("h", "History"),
            ("q", "Quit"),
        ]

        for i, (key, action) in enumerate(bindings):
            if i > 0:
                center.append(" │ ", style="dim")
            center.append(key, style="bold cyan")
            center.append(f" {action}", style="dim")

        # Right: View mode and resolver
        right = Text()
        view_labels = {
            "tree": "🌳 Tree",
            "diagram": "📊 Diagram",
            "table": "📋 Table",
        }
        right.append(view_labels.get(self._view_mode, self._view_mode), style="bold")
        right.append(" │ ", style="dim")
        right.append(f"DNS: {self._resolver}", style="dim")

        table.add_row(left, center, right)
        return table
