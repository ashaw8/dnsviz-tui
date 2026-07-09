"""DNSViz-style chain-of-trust graph.

Replicates the dnsviz.net "DNSSEC authentication chain" drawing in
characters: one bordered box per zone, individual DNSKEY nodes (alg, id,
bits) inside it, KSKs grey-filled with a self-signature loop, the root
trust anchor double-bordered, and KSK -> ZSK -> DS -> child-KSK edges
crossing the zone boundaries. RRset leaf nodes hang off the signing ZSK
of the target zone.

Pure Rich (no Textual imports) so it can be rendered and tested headless.
The diagram is painted onto a sparse character canvas and emitted as a
single non-wrapping Text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich.text import Text

from dnsviz_tui.models.chain import (
    DNSKeyInfo,
    TrustChain,
    ValidationStatus,
    ZoneInfo,
)

# dnsviz.net draws nodes and edges in teal; grey fill marks SEP keys.
EDGE = "#1f9e9e"
NODE = "#1f9e9e"
ANCHOR = f"bold {NODE}"
KSK_FILL = "on grey30"
ZONE_BORDER = "grey62"
INSECURE_EDGE = "yellow3"
BOGUS_EDGE = "red"

_NODE_GAP = 2          # columns between sibling nodes
_ZONE_GAP_ROWS = 3     # rows between zone boxes (the inter-zone trunk)
_LOOP_COLS = 2         # extra columns a self-loop needs right of a node

# IANA root trust anchor key tags (matches dnssec.ROOT_DS_RECORDS)
_ROOT_ANCHOR_TAGS = {20326, 38696}

_RR_ORDER = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "SPF", "DMARC"]


class Canvas:
    """Sparse grid of styled characters."""

    def __init__(self) -> None:
        self._rows: list[list[str]] = []
        self._styles: list[list[str]] = []

    def _ensure(self, y: int, x: int) -> None:
        while len(self._rows) <= y:
            self._rows.append([])
            self._styles.append([])
        row, styles = self._rows[y], self._styles[y]
        while len(row) <= x:
            row.append(" ")
            styles.append("")

    def put(self, y: int, x: int, ch: str, style: str = "") -> None:
        self._ensure(y, x)
        self._rows[y][x] = ch
        self._styles[y][x] = style

    def text(self, y: int, x: int, s: str, style: str = "") -> None:
        for i, ch in enumerate(s):
            self.put(y, x + i, ch, style)

    def hline(self, y: int, x0: int, x1: int, style: str = "", ch: str = "─") -> None:
        for x in range(min(x0, x1), max(x0, x1) + 1):
            self.put(y, x, ch, style)

    def vline(
        self, x: int, y0: int, y1: int, style: str = "", ch: str = "│",
        only_blank: bool = False,
    ) -> None:
        for y in range(min(y0, y1), max(y0, y1) + 1):
            if only_blank:
                self._ensure(y, x)
                if self._rows[y][x] != " ":
                    continue
            self.put(y, x, ch, style)

    @property
    def height(self) -> int:
        return len(self._rows)

    def to_text(self) -> Text:
        out = Text(no_wrap=True)
        for y, row in enumerate(self._rows):
            # Trim trailing blanks, batch same-style runs
            end = len(row)
            while end > 0 and row[end - 1] == " ":
                end -= 1
            x = 0
            while x < end:
                style = self._styles[y][x]
                run_end = x
                while run_end < end and self._styles[y][run_end] == style:
                    run_end += 1
                out.append("".join(row[x:run_end]), style=style or None)
                x = run_end
            out.append("\n")
        return out


_BORDERS = {
    "round": "╭╮╰╯─│",
    "double": "╔╗╚╝═║",
    "square": "┌┐└┘─│",
}


@dataclass
class _Node:
    """A painted node's geometry."""
    x: int = 0
    y: int = 0
    w: int = 0
    h: int = 0
    tag: Optional[int] = None    # DNSKEY key tag, when the node is a key

    @property
    def cx(self) -> int:
        return self.x + self.w // 2

    @property
    def bottom(self) -> int:
        return self.y + self.h - 1


def _node_width(lines: list[str]) -> int:
    return max(len(ln) for ln in lines) + 4


def _paint_node(
    cv: Canvas,
    y: int,
    x: int,
    lines: list[str],
    border: str = "round",
    style: str = NODE,
    fill: str = "",
    tag: Optional[int] = None,
) -> _Node:
    w = _node_width(lines)
    h = len(lines) + 2
    tl, tr, bl, br, hz, vt = _BORDERS[border]
    cv.text(y, x, tl + hz * (w - 2) + tr, style)
    for i, line in enumerate(lines):
        cv.put(y + 1 + i, x, vt, style)
        body_style = ("bold " if i == 0 else "") + fill
        cv.text(y + 1 + i, x + 1, line.center(w - 2), body_style.strip())
        cv.put(y + 1 + i, x + w - 1, vt, style)
    cv.text(y + h - 1, x, bl + hz * (w - 2) + br, style)
    return _Node(x=x, y=y, w=w, h=h, tag=tag)


def _paint_self_loop(cv: Canvas, node: _Node, style: str = EDGE) -> None:
    """Loop out of the right side and back in: the key signs its own RRset."""
    right = node.x + node.w
    cv.put(node.y, right, "◀", style)
    cv.put(node.y, right + 1, "╮", style)
    for yy in range(node.y + 1, node.bottom):
        cv.put(yy, right + 1, "│", style)
    cv.put(node.bottom, right, "─", style)
    cv.put(node.bottom, right + 1, "╯", style)


def _fan(cv: Canvas, y: int, src_cx: int, dst_cxs: list[int], style: str = EDGE) -> int:
    """Drop from src, rail across, arrow into each destination. 3 rows."""
    cv.put(y, src_cx, "│", style)
    lo = min(dst_cxs + [src_cx])
    hi = max(dst_cxs + [src_cx])
    if lo == hi:
        cv.put(y + 1, src_cx, "│", style)
        cv.put(y + 2, src_cx, "▼", style)
        return 3
    cv.hline(y + 1, lo, hi, style)
    for cx in dst_cxs:
        if cx == src_cx:
            # Line arrives from above AND continues down; rail on one or both sides
            ch = "├" if cx == lo else ("┤" if cx == hi else "┼")
        elif cx == lo:
            ch = "┌"
        elif cx == hi:
            ch = "┐"
        else:
            ch = "┬"
        cv.put(y + 1, cx, ch, style)
    if src_cx not in dst_cxs:
        ch = "└" if src_cx == lo else ("┘" if src_cx == hi else "┴")
        cv.put(y + 1, src_cx, ch, style)
    for cx in dst_cxs:
        cv.put(y + 2, cx, "▼", style)
    return 3


@dataclass
class _ZonePlan:
    zone: ZoneInfo
    is_root: bool
    is_target: bool
    top_keys: list[DNSKeyInfo] = field(default_factory=list)
    rest_keys: list[DNSKeyInfo] = field(default_factory=list)
    ds_lines: list[list[str]] = field(default_factory=list)   # DS-for-child nodes
    rr_groups: list[tuple[list[str], Optional[int]]] = field(default_factory=list)
    child_edge_style: str = EDGE

    def key_lines(self, k: DNSKeyInfo) -> list[str]:
        return ["DNSKEY", f"alg={k.algorithm}, id={k.key_tag}", f"{k.key_length} bits"]

    def row_width(self, rows: list[list[str]]) -> int:
        if not rows:
            return 0
        return sum(_node_width(r) for r in rows) + _NODE_GAP * (len(rows) - 1)

    @property
    def needed_width(self) -> int:
        top = self.row_width([self.key_lines(k) for k in self.top_keys]) + _LOOP_COLS
        rest = self.row_width([self.key_lines(k) for k in self.rest_keys])
        ds = self.row_width(self.ds_lines)
        # Try to fit every RRset leaf in one row (like dnsviz); the cap in
        # build_diagram bounds this and wrapping kicks in only when capped.
        rr = self.row_width([g[0] for g in self.rr_groups])
        label = len(self.zone.name) + 2
        return max(top, rest, ds, rr, label, 30)


def _split_key_rows(zone: ZoneInfo, is_root: bool) -> tuple[list[DNSKeyInfo], list[DNSKeyInfo]]:
    """Top row: the KSK(s) that anchor the zone (signs the DNSKEY RRset,
    matches the DS / trust anchor). Everything else goes below, ZSKs first —
    the same vertical order dnsviz draws."""
    keys = zone.dnskeys
    if not keys:
        return [], []
    signer_tags = {r.key_tag for r in zone.rrsigs if r.type_covered == "DNSKEY"}
    ds_tags = {ds.key_tag for ds in zone.ds_records}
    if is_root:
        ds_tags = ds_tags | _ROOT_ANCHOR_TAGS
    top = [k for k in keys if k.is_ksk and k.key_tag in signer_tags]
    if not top:
        top = [k for k in keys if k.is_ksk and k.key_tag in ds_tags]
    if not top:
        top = [k for k in keys if k.is_ksk][:1]
    if not top:
        top = keys[:1]
    rest = [k for k in keys if k not in top]
    rest.sort(key=lambda k: (k.is_ksk, k.key_tag))
    return top, rest


def _plan_zones(chain: TrustChain) -> list[_ZonePlan]:
    plans: list[_ZonePlan] = []
    zones = chain.zones
    target_name = zones[-1].name if zones else ""
    for i, zone in enumerate(zones):
        plan = _ZonePlan(
            zone=zone,
            is_root=(zone.name == "."),
            is_target=(zone.name == target_name),
        )
        plan.top_keys, plan.rest_keys = _split_key_rows(zone, plan.is_root)

        child = zones[i + 1] if i + 1 < len(zones) else None
        if child is not None:
            # The DS RRset for the child lives in this (parent) zone's box.
            seen: set[int] = set()
            for ds in child.ds_records:
                if ds.digest_type in seen:
                    continue
                seen.add(ds.digest_type)
                plan.ds_lines.append(["DS", f"digest alg={ds.digest_type}"])
            if child.ds_records and child.ds_validated:
                plan.child_edge_style = EDGE
            elif child.ds_records:
                plan.child_edge_style = BOGUS_EDGE
            else:
                plan.child_edge_style = INSECURE_EDGE

        if plan.is_target and zone.additional_records:
            groups: dict[str, Optional[int]] = {}
            for rec in zone.additional_records:
                if rec.record_type not in groups:
                    groups[rec.record_type] = rec.rrsig.key_tag if rec.rrsig else None
            domain = target_name.rstrip(".") or "."
            for rtype in sorted(
                groups, key=lambda t: _RR_ORDER.index(t) if t in _RR_ORDER else 99
            ):
                plan.rr_groups.append(([f"{domain}/{rtype}"], groups[rtype]))
        plans.append(plan)
    return plans


def _paint_row(
    cv: Canvas,
    y: int,
    zone_x: int,
    zone_w: int,
    nodes: list[tuple[list[str], str, str, str, Optional[int]]],
) -> list[_Node]:
    """Paint nodes side by side, centered in the zone. Each entry is
    (lines, border, style, fill, tag)."""
    total = sum(_node_width(n[0]) for n in nodes) + _NODE_GAP * (len(nodes) - 1)
    x = zone_x + max(2, (zone_w - total) // 2)
    out: list[_Node] = []
    for lines, border, style, fill, tag in nodes:
        node = _paint_node(cv, y, x, lines, border, style, fill, tag)
        out.append(node)
        x += node.w + _NODE_GAP
    return out


def build_diagram(chain: TrustChain, max_width: int = 100) -> Text:
    """Render the chain as a dnsviz-style graph."""
    cv = Canvas()
    plans = _plan_zones(chain)
    if not plans:
        return Text("No data", style="dim")

    zone_w = min(max(p.needed_width for p in plans) + 8, max(max_width, 44))
    zone_x = 1
    ts = chain.query_time.strftime("(%Y-%m-%d %H:%M:%S UTC)")

    y = 0
    # (exit_cx, exit_y_inside_parent | None, parent_bottom_border_y, style)
    pending_trunk: Optional[tuple[int, Optional[int], int, str]] = None

    for plan in plans:
        zone = plan.zone
        top_y = y
        y += 1  # top border row

        arrow_rows = 2 if pending_trunk else 1  # incoming edge, or just padding
        y += arrow_rows

        edge = EDGE if zone.status != ValidationStatus.BOGUS else BOGUS_EDGE
        key_row = lambda keys, anchor_ok: [
            (
                plan.key_lines(k),
                "double" if (anchor_ok and plan.is_root and k.key_tag in _ROOT_ANCHOR_TAGS) else "round",
                ANCHOR if (anchor_ok and plan.is_root and k.key_tag in _ROOT_ANCHOR_TAGS) else NODE,
                KSK_FILL if k.is_ksk else "",
                k.key_tag,
            )
            for k in keys
        ]

        top_nodes: list[_Node] = []
        rest_nodes: list[_Node] = []
        primary: Optional[_Node] = None

        if plan.top_keys:
            top_nodes = _paint_row(cv, y, zone_x, zone_w, key_row(plan.top_keys, True))
            for node in top_nodes:
                _paint_self_loop(cv, node, edge)
            primary = top_nodes[0]
            y += top_nodes[0].h

            if plan.rest_keys:
                rest_specs = key_row(plan.rest_keys, False)
                # Pre-compute destination centers by painting after the fan
                total = sum(_node_width(s[0]) for s in rest_specs) + _NODE_GAP * (len(rest_specs) - 1)
                x = zone_x + max(2, (zone_w - total) // 2)
                dst_cxs = []
                for spec in rest_specs:
                    w = _node_width(spec[0])
                    dst_cxs.append(x + w // 2)
                    x += w + _NODE_GAP
                y += _fan(cv, y, primary.cx, dst_cxs, edge)
                rest_nodes = _paint_row(cv, y, zone_x, zone_w, rest_specs)
                y += rest_nodes[0].h
        else:
            reason = zone.status_reason or "no DNSKEY records"
            cv.text(y + 1, zone_x + max(2, (zone_w - len(reason)) // 2), reason, "dim")
            y += 3

        ds_nodes: list[_Node] = []
        if plan.ds_lines and primary is not None:
            # The DS RRset is signed by the zone's ZSK (fall back to the KSK).
            zsk_nodes = [n for n in rest_nodes if n.tag is not None]
            src = next(
                (n for n in zsk_nodes for k in plan.rest_keys
                 if k.key_tag == n.tag and k.is_zsk),
                primary,
            )
            specs = [(lines, "round", NODE, "", None) for lines in plan.ds_lines]
            total = sum(_node_width(s[0]) for s in specs) + _NODE_GAP * (len(specs) - 1)
            x = zone_x + max(2, (zone_w - total) // 2)
            dst_cxs = []
            for spec in specs:
                w = _node_width(spec[0])
                dst_cxs.append(x + w // 2)
                x += w + _NODE_GAP
            y += _fan(cv, y, src.cx, dst_cxs, plan.child_edge_style)
            ds_nodes = _paint_row(cv, y, zone_x, zone_w, specs)
            y += ds_nodes[0].h

        if plan.rr_groups and primary is not None:
            # Fan the RRset leaves off the ZSK that signs them.
            signer_tags = [t for _, t in plan.rr_groups if t is not None]
            signer = signer_tags[0] if signer_tags else None
            all_nodes = rest_nodes + top_nodes
            src = next((n for n in all_nodes if n.tag == signer), None)
            if src is None:
                src = next(
                    (n for n in rest_nodes for k in plan.rest_keys
                     if k.key_tag == n.tag and k.is_zsk),
                    primary,
                )
            inner_w = zone_w - 6
            rows: list[list[list[str]]] = [[]]
            for lines, _tag in plan.rr_groups:
                trial = rows[-1] + [lines]
                trial_w = sum(_node_width(r) for r in trial) + _NODE_GAP * (len(trial) - 1)
                if rows[-1] and trial_w > inner_w:
                    rows.append([lines])
                else:
                    rows[-1].append(lines)
            src_cx = src.cx
            for row in rows:
                specs = [(lines, "round", NODE, "", None) for lines in row]
                total = sum(_node_width(s[0]) for s in specs) + _NODE_GAP * (len(specs) - 1)
                x = zone_x + max(2, (zone_w - total) // 2)
                dst_cxs = []
                for spec in specs:
                    w = _node_width(spec[0])
                    dst_cxs.append(x + w // 2)
                    x += w + _NODE_GAP
                y += _fan(cv, y, src_cx, dst_cxs, edge)
                painted = _paint_row(cv, y, zone_x, zone_w, specs)
                y += painted[0].h
                src_cx = painted[0].cx  # chain any wrapped row off the first leaf

        # Zone footer: name and query timestamp, bottom-left like dnsviz.
        y += 1
        cv.text(y, zone_x + 2, zone.name if zone.name == "." else zone.name.rstrip("."),
                f"bold {ZONE_BORDER}" if zone.status == ValidationStatus.SECURE else f"bold {zone.status.color}")
        y += 1
        cv.text(y, zone_x + 2, ts, "grey42")
        y += 1

        bottom_y = y
        border_style = ZONE_BORDER
        if zone.status == ValidationStatus.BOGUS:
            border_style = "red"
        elif zone.status == ValidationStatus.INSECURE:
            border_style = "yellow3"
        # Zone box border
        cv.text(top_y, zone_x, "┌" + "─" * (zone_w - 2) + "┐", border_style)
        for yy in range(top_y + 1, bottom_y):
            cv.put(yy, zone_x, "│", border_style)
            cv.put(yy, zone_x + zone_w - 1, "│", border_style)
        cv.text(bottom_y, zone_x, "└" + "─" * (zone_w - 2) + "┘", border_style)

        # Incoming trunk from the parent's DS node, crossing both borders.
        if pending_trunk:
            exit_cx, exit_y, parent_border_y, style = pending_trunk
            entry = primary if primary is not None else _Node(
                x=zone_x + zone_w // 2, y=top_y + arrow_rows + 1, w=0, h=1
            )
            if exit_y is not None:
                # The exit line crosses the parent's footer rows; the zone
                # label and timestamp win, as in dnsviz.
                cv.vline(exit_cx, exit_y, parent_border_y - 1, style, only_blank=True)
            cv.put(parent_border_y, exit_cx, "┼", style)
            g0, g1, g2 = parent_border_y + 1, parent_border_y + 2, parent_border_y + 3
            if exit_cx == entry.cx:
                cv.vline(exit_cx, g0, g2, style, ch="┃")
            else:
                cv.put(g0, exit_cx, "┃", style)
                cv.hline(g1, min(exit_cx, entry.cx), max(exit_cx, entry.cx), style)
                cv.put(g1, exit_cx, "└" if exit_cx < entry.cx else "┘", style)
                cv.put(g1, entry.cx, "┐" if exit_cx < entry.cx else "┌", style)
                cv.put(g2, entry.cx, "┃", style)
            cv.put(top_y, entry.cx, "┼", style)
            cv.put(top_y + 1, entry.cx, "│", style)
            cv.put(top_y + 2, entry.cx, "▼", style)

        # Prepare the trunk for the next zone.
        if ds_nodes:
            pending_trunk = (ds_nodes[0].cx, ds_nodes[0].bottom + 1, bottom_y, plan.child_edge_style)
        else:
            pending_trunk = (zone_x + zone_w // 2, None, bottom_y, plan.child_edge_style)

        y = bottom_y + 1 + _ZONE_GAP_ROWS

    return cv.to_text()
