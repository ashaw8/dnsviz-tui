"""Entry point for dnsviz-tui."""

from dnsviz_tui.app import DNSVizApp


def main() -> None:
    """Run the DNSViz TUI application."""
    app = DNSVizApp()
    app.run()


if __name__ == "__main__":
    main()
