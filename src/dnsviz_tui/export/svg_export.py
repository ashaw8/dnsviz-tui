"""SVG export of a view's full content, independent of the visible screen.

Rich's own SVG export (and Textual's screenshots, which use it) emits runs of
text that only line up when the viewer has the Fira Code web font; with any
other font, box-drawing characters drift apart and vertical lines break
between rows. Here every character cell is placed explicitly instead: box
drawing and arrow characters become vector geometry that spans the full
cell, and every other glyph is centred in its own cell, so the result looks
the same in any viewer with any monospace font.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from html import escape
from io import StringIO
from pathlib import Path

from rich.cells import cell_len
from rich.color import Color, blend_rgb
from rich.color_triplet import ColorTriplet
from rich.console import Console, RenderableType
from rich.style import Style
from rich.terminal_theme import MONOKAI, TerminalTheme

# Fallback when no theme is passed: Textual's dark ANSI palette on the app's
# #0a0a0a background. The app passes the live theme so exports match the TUI.
DEFAULT_THEME = TerminalTheme(
    (10, 10, 10),
    (224, 224, 224),
    [MONOKAI.ansi_colors[i] for i in range(8)],
    [MONOKAI.ansi_colors[i] for i in range(8, 16)],
)

CELL_W = 10.0
CELL_H = 20.0
FONT_SIZE = 15.0
PAD = 20.0
_FONTS = "'DejaVu Sans Mono','Noto Sans Mono','Liberation Mono','Fira Code',Menlo,Consolas,monospace"

_LIGHT, _HEAVY, _DOUBLE = 1, 2, 3
_DIRS = {
    "UP": ("u",), "DOWN": ("d",), "LEFT": ("l",), "RIGHT": ("r",),
    "VERTICAL": ("u", "d"), "HORIZONTAL": ("l", "r"),
}
_WEIGHTS = {"LIGHT": _LIGHT, "SINGLE": _LIGHT, "HEAVY": _HEAVY, "DOUBLE": _DOUBLE}

# Filled triangles used as arrowheads: points in cell-relative units (0..1).
_TRIANGLES = {
    "▼": [(0.15, 0.3), (0.85, 0.3), (0.5, 0.8)],
    "▲": [(0.15, 0.7), (0.85, 0.7), (0.5, 0.2)],
    "▶": [(0.2, 0.2), (0.2, 0.8), (0.85, 0.5)],
    "◀": [(0.8, 0.2), (0.8, 0.8), (0.15, 0.5)],
    "▾": [(0.25, 0.4), (0.75, 0.4), (0.5, 0.7)],
    "▴": [(0.25, 0.6), (0.75, 0.6), (0.5, 0.3)],
    "▸": [(0.3, 0.3), (0.3, 0.7), (0.75, 0.5)],
    "◂": [(0.7, 0.3), (0.7, 0.7), (0.25, 0.5)],
}


@lru_cache(maxsize=None)
def _box_parts(ch: str) -> tuple[dict[str, int], bool] | None:
    """Decode a box-drawing character from its Unicode name into
    {direction: weight} plus whether it is a rounded corner."""
    if not "─" <= ch <= "╿":
        return None
    name = unicodedata.name(ch, "")
    if "DIAGONAL" in name or not name.startswith("BOX DRAWINGS "):
        return None
    name = name.removeprefix("BOX DRAWINGS ")
    for dash in ("DOUBLE DASH", "TRIPLE DASH", "QUADRUPLE DASH"):
        name = name.replace(dash, "")
    arc = " ARC " in f" {name} "
    dirs: dict[str, int] = {}
    weight = _LIGHT
    for part in name.split(" AND "):
        words = part.split()
        weight = next((_WEIGHTS[w] for w in words if w in _WEIGHTS), weight)
        for w in words:
            for d in _DIRS.get(w, ()):
                dirs[d] = weight
    return (dirs, arc) if dirs else None


def _box_svg(ch: str, x: float, y: float, color: str, segs: list) -> list[str] | None:
    """Draw a box-drawing character. Straight strokes are appended to `segs`
    for merging (see _merge_segments); curved ones are returned as SVG."""
    parts = _box_parts(ch)
    if parts is None:
        return None
    dirs, arc = parts
    cx, cy = x + CELL_W / 2, y + CELL_H / 2
    edge = {"u": (cx, y), "d": (cx, y + CELL_H), "l": (x, cy), "r": (x + CELL_W, cy)}
    light = CELL_W * 0.11
    out: list[str] = []

    def stroke(x1: float, y1: float, x2: float, y2: float, sw: float) -> None:
        if y1 == y2:
            segs.append((color, round(sw, 2), "h", round(y1, 2), min(x1, x2), max(x1, x2)))
        else:
            segs.append((color, round(sw, 2), "v", round(x1, 2), min(y1, y2), max(y1, y2)))

    if arc:
        (a, b) = list(dirs)
        (ax, ay), (bx, by) = edge[a], edge[b]
        out.append(f'<path d="M{ax:.1f},{ay:.1f} Q{cx:.1f},{cy:.1f} {bx:.1f},{by:.1f}" '
                   f'fill="none" stroke="{color}" stroke-width="{light:.2f}"/>')
        return out

    o = CELL_W * 0.18  # half-gap between the two strokes of a double line
    for d, w in dirs.items():
        ex, ey = edge[d]
        if w != _DOUBLE:
            sw = light * (2.2 if w == _HEAVY else 1)
            # Extend past the centre by half a stroke so corners close cleanly.
            sx = cx + (-sw / 2 if d == "r" else sw / 2 if d == "l" else 0)
            sy = cy + (-sw / 2 if d == "d" else sw / 2 if d == "u" else 0)
            stroke(sx, sy, ex, ey, sw)
            continue
        horizontal = d in ("l", "r")
        sign = 1 if d in ("r", "d") else -1
        for side in (-1, 1):
            # A stroke stops short of the centre if a perpendicular line
            # leaves on its side, meets the outer stroke if one leaves on the
            # other side, and runs to the centre otherwise.
            # side -1 is the stroke above (horizontal) or left of (vertical) centre.
            near, far = ("u", "d") if horizontal else ("l", "r")
            mine, other = (near, far) if side == -1 else (far, near)
            if mine in dirs:
                start = o
            elif other in dirs:
                start = -o
            else:
                start = 0
            if horizontal:
                x1, y1 = cx + sign * start, cy + side * o
                x2, y2 = ex, y1
            else:
                x1, y1 = cx + side * o, cy + sign * start
                x2, y2 = x1, ey
            stroke(x1, y1, x2, y2, light)
    return out


def _merge_segments(segs: list) -> list[str]:
    """Join collinear touching strokes of the same colour and width into one
    line. Drawing each cell's half-strokes separately makes anti-aliased lines
    render twice where they overlap, which shows up as a dashed pattern."""
    groups: dict[tuple, list[tuple[float, float]]] = {}
    for color, sw, orient, fixed, a, b in segs:
        groups.setdefault((color, sw, orient, fixed), []).append((a, b))
    out = []
    for (color, sw, orient, fixed), spans in groups.items():
        spans.sort()
        merged = [list(spans[0])]
        for a, b in spans[1:]:
            if a <= merged[-1][1] + 0.01:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        for a, b in merged:
            x1, y1, x2, y2 = (a, fixed, b, fixed) if orient == "h" else (fixed, a, fixed, b)
            out.append(f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
                       f'stroke="{color}" stroke-width="{sw:.2f}"/>')
    return out


def _hex(c: ColorTriplet) -> str:
    return c.hex


def _resolve(style: Style | None, theme: TerminalTheme) -> tuple[str, str | None, bool, bool, bool]:
    """(fg hex, bg hex or None, bold, italic, underline) for a cell."""
    style = style or Style()
    fg = style.color.get_truecolor(theme, foreground=True) if style.color else theme.foreground_color
    bg = style.bgcolor.get_truecolor(theme, foreground=False) if style.bgcolor else None
    if style.reverse:
        fg, bg = (bg or theme.background_color), fg
    if style.dim:
        fg = blend_rgb(fg, bg or theme.background_color, 0.4)
    return _hex(fg), (_hex(bg) if bg else None), bool(style.bold), bool(style.italic), bool(style.underline)


def _render_svg(lines, width: int, title: str, theme: TerminalTheme) -> str:
    rows = len(lines)
    body_w = width * CELL_W + 2 * PAD
    body_h = rows * CELL_H + 2 * PAD
    bg_rects: list[str] = []
    marks: list[str] = []
    glyphs: list[str] = []
    segs: list = []

    for row, line in enumerate(lines):
        y = PAD + row * CELL_H
        col = 0
        run_bg, run_start = None, 0
        for segment in line:
            if segment.control:
                continue
            fg, bg, bold, italic, underline = _resolve(segment.style, theme)
            for ch in segment.text:
                w = cell_len(ch)
                if w == 0:
                    continue
                x = PAD + col * CELL_W
                if bg != run_bg:
                    if run_bg:
                        bg_rects.append(_rect(run_start, col, y, run_bg))
                    run_bg, run_start = bg, col
                if ch != " ":
                    if ch in _TRIANGLES:
                        pts = " ".join(f"{x + px * CELL_W:.1f},{y + py * CELL_H:.1f}" for px, py in _TRIANGLES[ch])
                        marks.append(f'<polygon points="{pts}" fill="{fg}"/>')
                    elif ch == "█":
                        marks.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{CELL_W * w:.1f}" '
                                     f'height="{CELL_H:.1f}" fill="{fg}"/>')
                    else:
                        box = _box_svg(ch, x, y, fg, segs)
                        if box is not None:
                            marks.extend(box)
                        else:
                            attrs = f' font-weight="bold"' if bold else ""
                            attrs += ' font-style="italic"' if italic else ""
                            glyphs.append(
                                f'<text x="{x + CELL_W * w / 2:.1f}" y="{y + CELL_H * 0.72:.1f}" '
                                f'fill="{fg}"{attrs}>{escape(ch)}</text>'
                            )
                if underline:
                    marks.append(f'<line x1="{x:.1f}" y1="{y + CELL_H - 2:.1f}" x2="{x + CELL_W * w:.1f}" '
                                 f'y2="{y + CELL_H - 2:.1f}" stroke="{fg}" stroke-width="1"/>')
                col += w
        if run_bg:
            bg_rects.append(_rect(run_start, col, y, run_bg))

    marks = _merge_segments(segs) + marks
    background = _hex(theme.background_color)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{body_w:.0f}" height="{body_h:.0f}" '
        f'viewBox="0 0 {body_w:.0f} {body_h:.0f}" data-cols="{width}" data-rows="{rows}">\n'
        f"<title>{escape(title)}</title>\n"
        # Absolute size: Qt's SVG renderer (Gwenview, Okular) reads "100%" as
        # 100px, leaving the rest transparent.
        f'<rect width="{body_w:.0f}" height="{body_h:.0f}" rx="8" fill="{background}"/>\n'
        f'<g shape-rendering="crispEdges">{"".join(bg_rects)}</g>\n'
        f'<g stroke-linecap="butt">{"".join(marks)}</g>\n'
        f'<g font-family="{_FONTS}" font-size="{FONT_SIZE}" text-anchor="middle">\n'
        + "\n".join(glyphs)
        + "\n</g>\n</svg>\n"
    )


def _rect(c0: int, c1: int, y: float, color: str) -> str:
    return (f'<rect x="{PAD + c0 * CELL_W:.1f}" y="{y:.1f}" width="{(c1 - c0) * CELL_W:.1f}" '
            f'height="{CELL_H:.1f}" fill="{color}"/>')


def export_svg(
    renderable: RenderableType,
    output_path: Path,
    width: int,
    title: str = "dnsviz-tui",
    theme: TerminalTheme | None = None,
) -> None:
    """Render to an offscreen console with unbounded height and save as SVG.

    Unlike App.save_screenshot(), this captures the whole renderable rather
    than the terminal viewport, so nothing scrolled out of view is lost and
    no surrounding UI (header, sidebar, footer) is included.

    `theme` supplies the default foreground/background and the ANSI palette;
    pass the app's live colours (see DNSVizApp._export_theme) so the export
    matches the TUI's current theme.
    """
    console = Console(
        width=width,
        file=StringIO(),
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    lines = console.render_lines(renderable, console.options, pad=False)
    # Drop trailing blank lines so the image ends at the content.
    while lines and not "".join(s.text for s in lines[-1]).strip():
        lines.pop()
    Path(output_path).write_text(_render_svg(lines, width, title, theme or DEFAULT_THEME), encoding="utf-8")
