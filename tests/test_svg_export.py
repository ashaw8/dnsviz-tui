"""Tests for the full-content SVG screenshot export."""

import re
from html import unescape

import pytest

from dnsviz_tui.export.svg_export import CELL_H, CELL_W, PAD, _box_parts, export_svg
from dnsviz_tui.views.diagram_view import DiagramView
from tests.test_graph import _secure_chain


def _svg_rows(path) -> list[str]:
    """Rebuild each row's text from the individually placed glyphs.
    Box-drawing characters are drawn as geometry, so they show up as spaces."""
    svg = path.read_text()
    rows: dict[int, dict[int, str]] = {}
    for x, y, ch in re.findall(r'<text x="([\d.]+)" y="([\d.]+)"[^>]*>([^<]+)</text>', svg):
        row = int((float(y) - PAD) // CELL_H)
        col = int((float(x) - PAD) // CELL_W)
        rows.setdefault(row, {})[col] = unescape(ch)
    n = int(re.search(r'data-rows="(\d+)"', svg).group(1))
    return ["".join(rows.get(r, {}).get(c, " ") for c in range(max(rows.get(r, {0: ""}), default=0) + 1))
            for r in range(n)]


def _svg_text(path) -> str:
    return "\n".join(_svg_rows(path))


def test_export_svg_contains_entire_diagram(tmp_path):
    chain = _secure_chain()
    out = tmp_path / "diagram.svg"
    export_svg(DiagramView(chain=chain).render(), out, width=110)

    text = _svg_text(out)
    for zone in chain.zones:
        for key in zone.dnskeys:
            assert f"id={key.key_tag}" in text
    assert "Chain of Trust - Diagram View" in text


def test_box_drawing_is_geometry_not_font_glyphs(tmp_path):
    """Lines must not depend on the viewer's font: no box-drawing or arrow
    characters are left as text."""
    out = tmp_path / "diagram.svg"
    export_svg(DiagramView(chain=_secure_chain()).render(), out, width=110)
    glyphs = "".join(re.findall(r"<text[^>]*>([^<]+)</text>", out.read_text()))
    assert not re.search("[─-╿▼▲◀▶]", glyphs)
    assert "<line" in out.read_text() and "<polygon" in out.read_text()


def test_collinear_strokes_are_merged(tmp_path):
    """Overlapping per-cell strokes render as a dashed line when anti-aliased;
    each straight run must be emitted once."""
    out = tmp_path / "diagram.svg"
    export_svg(DiagramView(chain=_secure_chain()).render(), out, width=110)
    seen: dict[tuple, list[tuple[float, float]]] = {}
    for x1, y1, x2, y2, color, sw in re.findall(
        r'<line x1="([\d.]+)" y1="([\d.]+)" x2="([\d.]+)" y2="([\d.]+)" stroke="(#\w+)" stroke-width="([\d.]+)"',
        out.read_text(),
    ):
        if y1 == y2:
            key, span = ("h", y1, color, sw), (float(x1), float(x2))
        else:
            key, span = ("v", x1, color, sw), (float(y1), float(y2))
        for a, b in seen.get(key, []):
            assert span[1] <= a - 0.01 or span[0] >= b + 0.01, f"overlapping strokes {key} {span} {(a, b)}"
        seen.setdefault(key, []).append(span)


def test_box_parts_decodes_weights_and_arcs():
    assert _box_parts("─") == ({"l": 1, "r": 1}, False)
    assert _box_parts("╭") == ({"d": 1, "r": 1}, True)
    assert _box_parts("╔") == ({"d": 3, "r": 3}, False)
    assert _box_parts("┡") == ({"d": 1, "r": 2, "u": 2}, False)
    assert _box_parts("┃") == ({"u": 2, "d": 2}, False)
    assert _box_parts("a") is None


@pytest.mark.asyncio
async def test_screenshot_exports_whole_graph_not_screen(tmp_path, monkeypatch):
    """In a terminal too short to show the graph, 's' still saves all of it,
    and none of the surrounding UI."""
    from dnsviz_tui.app import DNSVizApp

    monkeypatch.chdir(tmp_path)
    chain = _secure_chain()
    app = DNSVizApp()
    async with app.run_test(size=(120, 30)) as pilot:
        app._set_chain(chain)
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()

    [svg] = (tmp_path / "exports").glob("*.svg")
    rows = _svg_rows(svg)
    text = "\n".join(rows)
    for zone in chain.zones:
        for key in zone.dnskeys:
            assert f"id={key.key_tag}" in text
    assert len(rows) > 30                  # taller than the 30-row terminal
    assert "Press / to query" not in text  # no input box placeholder / welcome text
    assert "Screenshot" not in text        # no footer key bindings


def test_background_has_absolute_size(tmp_path):
    """Qt's SVG renderer (Gwenview, Okular) treats width="100%" as 100px."""
    out = tmp_path / "diagram.svg"
    export_svg(DiagramView(chain=_secure_chain()).render(), out, width=110)
    svg = out.read_text()
    w, h = re.search(r'<svg[^>]* width="(\d+)" height="(\d+)"', svg).groups()
    assert f'<rect width="{w}" height="{h}"' in svg
    assert "100%" not in svg


@pytest.mark.parametrize("theme", ["textual-dark", "textual-light", "nord"])
async def test_screenshot_follows_tui_theme(tmp_path, monkeypatch, theme):
    """The export uses the colours the view is drawn with in the active theme."""
    from dnsviz_tui.app import DNSVizApp

    monkeypatch.chdir(tmp_path)
    app = DNSVizApp()
    async with app.run_test(size=(120, 30)) as pilot:
        app.theme = theme
        app._set_chain(_secure_chain())
        await pilot.press("2")
        await pilot.pause()
        _, _, background, foreground = app.query_one("#diagram-view").colors
        await pilot.press("s")
        await pilot.pause()

    [svg] = (tmp_path / "exports").glob("*.svg")
    text = svg.read_text()
    page = re.search(r'<rect width="\d+" height="\d+" rx="8" fill="(#\w+)"', text).group(1)
    assert page.lower() == background.hex.lower()
    # Default-coloured text (e.g. the "DNSKEY" node labels) uses the view's foreground.
    assert f'fill="{foreground.hex.lower()}"' in text.lower()
