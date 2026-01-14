"""History panel widget for showing query history."""

from textual.widgets import Static, ListView, ListItem, Label
from textual.containers import Vertical
from textual.message import Message
from rich.text import Text
from rich.panel import Panel

from dnsviz_tui.models.chain import TrustChain, ValidationStatus


class HistoryItem(ListItem):
    """A single history item."""

    DEFAULT_CSS = """
    HistoryItem {
        height: 3;
        padding: 0 1;
        background: transparent;
    }

    HistoryItem:hover {
        background: #1f1f1f;
    }

    HistoryItem.-selected {
        background: #2a2a2a;
    }
    """

    def __init__(self, chain: TrustChain, index: int):
        super().__init__()
        self.chain = chain
        self.index = index

    def compose(self):
        """Compose the history item."""
        status = self.chain.overall_status

        # Domain name (truncate if needed)
        domain = self.chain.target_domain.rstrip('.')
        if len(domain) > 18:
            domain = domain[:15] + "..."

        text = Text()
        text.append(f"{status.symbol} ", style=status.color)
        text.append(domain, style="grey70")
        yield Label(text)


class HistoryPanel(Static):
    """Panel showing query history."""

    DEFAULT_CSS = """
    HistoryPanel {
        width: 100%;
        height: 100%;
        background: #111;
        padding: 0;
    }

    HistoryPanel #history-header {
        height: 3;
        background: #1a1a1a;
        color: #666;
        text-align: center;
        padding: 1 1;
        text-style: bold;
        border-bottom: solid #252525;
    }

    HistoryPanel #history-list {
        height: 1fr;
        background: #111;
        scrollbar-size: 1 1;
    }

    HistoryPanel #empty-message {
        color: #444;
        text-align: center;
        padding: 2 1;
    }
    """

    class HistorySelected(Message):
        """Message sent when a history item is selected."""

        def __init__(self, chain: TrustChain):
            super().__init__()
            self.chain = chain

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._history: list[TrustChain] = []

    def compose(self):
        """Compose the history panel."""
        yield Static("HISTORY", id="history-header")
        yield Static("No queries yet", id="empty-message")
        yield ListView(id="history-list")

    def add_entry(self, chain: TrustChain) -> None:
        """Add a new entry to the history."""
        # Don't add duplicates
        for existing in self._history:
            if existing.target_domain == chain.target_domain:
                self._history.remove(existing)
                break

        self._history.insert(0, chain)
        self._rebuild_list()

    def _rebuild_list(self) -> None:
        """Rebuild the history list view."""
        list_view = self.query_one("#history-list", ListView)
        empty_msg = self.query_one("#empty-message", Static)

        list_view.clear()

        if self._history:
            empty_msg.display = False
            for i, chain in enumerate(self._history):
                item = HistoryItem(chain, i)
                list_view.append(item)
        else:
            empty_msg.display = True

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle history item selection."""
        if isinstance(event.item, HistoryItem):
            self.post_message(self.HistorySelected(event.item.chain))

    def clear_history(self) -> None:
        """Clear all history."""
        self._history.clear()
        self._rebuild_list()

    @property
    def history(self) -> list[TrustChain]:
        """Get the history list."""
        return self._history.copy()
