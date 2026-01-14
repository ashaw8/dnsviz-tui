"""Main Textual application for dnsviz-tui."""

from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Input, Static, Label
from textual.screen import ModalScreen
from textual import work

from dnsviz_tui.dns.resolver import DNSResolver
from dnsviz_tui.dns.dnssec import DNSSECValidator
from dnsviz_tui.models.chain import TrustChain, ValidationStatus
from dnsviz_tui.views.tree_view import TreeView
from dnsviz_tui.views.diagram_view import DiagramView
from dnsviz_tui.views.table_view import TableView
from dnsviz_tui.widgets.domain_input import DomainInput
from dnsviz_tui.widgets.history_panel import HistoryPanel
from dnsviz_tui.export.json_export import export_json
from dnsviz_tui.export.text_export import export_text


class ExportModal(ModalScreen[str | None]):
    """Modal dialog for export options."""

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
    ]

    DEFAULT_CSS = """
    ExportModal {
        align: center middle;
    }

    ExportModal > Container {
        width: 50;
        height: auto;
        border: solid #444;
        background: #1a1a1a;
        padding: 1 2;
    }

    ExportModal .title {
        text-style: bold;
        text-align: center;
        padding-bottom: 1;
        color: #e0e0e0;
    }

    ExportModal .buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }

    ExportModal .btn {
        margin: 0 1;
        min-width: 12;
        color: #888;
    }
    """

    def __init__(self, chain: TrustChain):
        super().__init__()
        self.chain = chain

    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Export Results", classes="title")
            yield Label(f"Domain: {self.chain.target_domain}")
            yield Label("")
            yield Label("Choose format:")
            with Horizontal(classes="buttons"):
                yield Static("[1] JSON", classes="btn", id="btn-json")
                yield Static("[2] Text", classes="btn", id="btn-text")
                yield Static("[3] Both", classes="btn", id="btn-both")

    def key_1(self) -> None:
        self._export("json")

    def key_2(self) -> None:
        self._export("text")

    def key_3(self) -> None:
        self._export("both")

    def _export(self, format: str) -> None:
        """Perform export and dismiss."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = self.chain.target_domain.rstrip('.').replace('.', '_')
        base_path = Path("exports") / f"{domain_safe}_{timestamp}"

        exported = []

        if format in ("json", "both"):
            json_path = base_path.with_suffix(".json")
            export_json(self.chain, json_path)
            exported.append(str(json_path))

        if format in ("text", "both"):
            text_path = base_path.with_suffix(".txt")
            export_text(self.chain, text_path)
            exported.append(str(text_path))

        self.dismiss(", ".join(exported))


class ResolverModal(ModalScreen[list[str] | None]):
    """Modal dialog for resolver configuration."""

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
    ]

    DEFAULT_CSS = """
    ResolverModal {
        align: center middle;
    }

    ResolverModal > Container {
        width: 60;
        height: auto;
        border: solid #444;
        background: #1a1a1a;
        padding: 1 2;
    }

    ResolverModal .title {
        text-style: bold;
        text-align: center;
        padding-bottom: 1;
        color: #e0e0e0;
    }

    ResolverModal Input {
        margin: 1 0;
        background: #252525;
        border: solid #333;
    }

    ResolverModal .hint {
        color: #666;
        text-style: italic;
    }
    """

    def __init__(self, current: list[str]):
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Configure DNS Resolver", classes="title")
            yield Label("Enter resolver IPs (comma-separated):")
            yield Input(
                value=", ".join(self.current),
                placeholder="e.g., 8.8.8.8, 1.1.1.1",
                id="resolver-input"
            )
            yield Label("Common: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9)", classes="hint")
            yield Label("")
            yield Label("Press Enter to apply, Escape to cancel")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle resolver input submission."""
        value = event.value.strip()
        if value:
            resolvers = [r.strip() for r in value.split(",") if r.strip()]
            self.dismiss(resolvers)
        else:
            self.dismiss(None)


class DNSVizApp(App):
    """Main dnsviz-tui application."""

    TITLE = "dnsviz-tui"
    SUB_TITLE = "DNSSEC Chain of Trust"

    CSS = """
    Screen {
        background: #0a0a0a;
        layout: grid;
        grid-size: 1;
        grid-rows: auto 1fr auto;
    }

    Header {
        dock: top;
        height: 1;
        background: #151515;
        color: #888;
    }

    Footer {
        dock: bottom;
        height: 1;
        background: #151515;
    }

    #main-layout {
        layout: horizontal;
        height: 100%;
    }

    #sidebar {
        width: 24;
        background: #101010;
        border-right: solid #222;
    }

    #content {
        width: 1fr;
    }

    #domain-input {
        dock: top;
        height: 3;
        margin: 1;
        background: #151515;
        border: solid #333;
        color: #ddd;
    }

    #domain-input:focus {
        border: solid #4a9eff;
    }

    #view-area {
        height: 1fr;
        overflow-y: auto;
        background: #0a0a0a;
        padding: 0 1;
    }

    #result-display {
        color: #555;
        padding: 2;
    }

    #tree-view, #diagram-view, #table-view {
        background: #0a0a0a;
    }

    .hidden {
        display: none;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "unfocus", "Back", priority=True),
        Binding("slash", "focus_input", "Query"),
        Binding("1", "view_tree", "Tree"),
        Binding("2", "view_diagram", "Diagram"),
        Binding("3", "view_table", "Table"),
        Binding("e", "export", "Export"),
        Binding("r", "resolver", "Resolver"),
    ]

    def __init__(self):
        super().__init__()
        self._resolver = DNSResolver()
        self._validator = DNSSECValidator(self._resolver)
        self._current_chain: TrustChain | None = None
        self._current_view = "tree"
        self._is_loading = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            with Container(id="sidebar"):
                yield HistoryPanel(id="history-panel")
            with Vertical(id="content"):
                yield DomainInput(id="domain-input")
                with ScrollableContainer(id="view-area"):
                    yield Static("Press / to query a domain\n\nExamples: cloudflare.com, google.com", id="result-display")
                    yield TreeView(id="tree-view", classes="hidden")
                    yield DiagramView(id="diagram-view", classes="hidden")
                    yield TableView(id="table-view", classes="hidden")
        yield Footer()

    def on_mount(self) -> None:
        self.set_focus(None)  # Start with footer visible

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "domain-input":
            domain = event.value.strip()
            if domain and not self._is_loading:
                self._query_domain(domain)

    @work(thread=True)
    def _query_domain(self, domain: str) -> None:
        self.call_from_thread(self._set_loading, True, domain)
        try:
            chain = self._validator.validate_chain(domain)
            self.call_from_thread(self._set_chain, chain)
        except Exception as e:
            import traceback
            self.call_from_thread(self._handle_error, f"{e}\n{traceback.format_exc()}")
        finally:
            self.call_from_thread(self._set_loading, False, domain)

    def _handle_error(self, error: str) -> None:
        self.notify("Error occurred", severity="error", timeout=5)
        result = self.query_one("#result-display", Static)
        result.update(f"Error:\n\n{error}")
        result.remove_class("hidden")
        for v in ["tree", "diagram", "table"]:
            self.query_one(f"#{v}-view").add_class("hidden")

    def _set_loading(self, loading: bool, domain: str) -> None:
        self._is_loading = loading
        if loading:
            result = self.query_one("#result-display", Static)
            result.update(f"⏳ Querying {domain}...")
            result.remove_class("hidden")
            for v in ["tree", "diagram", "table"]:
                self.query_one(f"#{v}-view").add_class("hidden")

    def _set_chain(self, chain: TrustChain) -> None:
        self._current_chain = chain
        self.query_one("#result-display").add_class("hidden")

        self.query_one("#tree-view", TreeView).set_chain(chain)
        self.query_one("#diagram-view", DiagramView).set_chain(chain)
        self.query_one("#table-view", TableView).set_chain(chain)

        self._switch_view(self._current_view)
        self.query_one("#history-panel", HistoryPanel).add_entry(chain)

        status = chain.overall_status
        self.notify(
            f"{chain.target_domain}: {status.symbol} {status.value.upper()}",
            severity="information" if status == ValidationStatus.SECURE else "warning",
            timeout=4
        )
        self.set_focus(None)

    def _switch_view(self, view_name: str) -> None:
        if not self._current_chain:
            return
        self.query_one("#result-display").add_class("hidden")
        for v in ["tree", "diagram", "table"]:
            widget = self.query_one(f"#{v}-view")
            if v == view_name:
                widget.remove_class("hidden")
            else:
                widget.add_class("hidden")
        self._current_view = view_name

    def action_unfocus(self) -> None:
        self.set_focus(None)

    def action_view_tree(self) -> None:
        self._switch_view("tree")

    def action_view_diagram(self) -> None:
        self._switch_view("diagram")

    def action_view_table(self) -> None:
        self._switch_view("table")

    def action_export(self) -> None:
        if not self._current_chain:
            self.notify("No data to export", severity="warning")
            return
        self.push_screen(ExportModal(self._current_chain), lambda r: self.notify(f"Exported: {r}") if r else None)

    def action_resolver(self) -> None:
        def handle(result):
            if result:
                self._resolver.set_nameservers(result)
                self._validator = DNSSECValidator(self._resolver)
                self.notify(f"Resolver: {', '.join(result)}")
        self.push_screen(ResolverModal(self._resolver.nameservers), handle)

    def action_focus_input(self) -> None:
        self.query_one("#domain-input").focus()

    def on_history_panel_history_selected(self, event: HistoryPanel.HistorySelected) -> None:
        self._set_chain(event.chain)


if __name__ == "__main__":
    app = DNSVizApp()
    app.run()
