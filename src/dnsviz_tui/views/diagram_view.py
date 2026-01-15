"""ASCII diagram view visualization for DNSSEC chain of trust."""

from rich.console import RenderableType, Group
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
    CORNER_BL = "└"
    CORNER_TR = "┐"
    LINE_V = "│"
    LINE_H = "─"
    ARROW_D = "▼"
    ARROW_R = "▶"

    def __init__(self, chain: TrustChain | None = None, **kwargs):
        super().__init__(**kwargs)
        self._chain = chain

    def set_chain(self, chain: TrustChain) -> None:
        """Set the trust chain to display."""
        self._chain = chain
        self.refresh()

    def _build_waterfall_chain(self) -> Text:
        """Build centered waterfall/staircase chain diagram (trust chain only)."""
        if not self._chain or not self._chain.zones:
            return Text("No data")

        zones = self._chain.zones
        box_width = 22
        indent_step = 8

        # Calculate total width of the diagram
        total_diagram_width = (len(zones) - 1) * indent_step + box_width

        # Center the diagram (assume ~80 char width, adjust offset to center)
        center_offset = max(10, (70 - total_diagram_width) // 2)

        result = Text()

        for i, zone in enumerate(zones):
            indent = " " * (center_offset + i * indent_step)

            # Draw zone box
            self._draw_zone_box(result, zone, indent, box_width)

            # Draw connector to next zone (except for last)
            if i < len(zones) - 1:
                next_zone = zones[i + 1]
                self._draw_connector(result, zone, next_zone, indent, box_width, indent_step, center_offset, i)

        return result

    def _build_attached_records_diagram(self) -> RenderableType | None:
        """Build attached additional records diagram using dynamic layout."""
        if not self._chain:
            return None

        target_zone = self._chain.target_zone
        if not target_zone or not target_zone.additional_records:
            return None

        records = target_zone.additional_records

        # Group records by type
        records_by_type = {}
        for record in records:
            rtype = record.record_type
            if rtype not in records_by_type:
                records_by_type[rtype] = []
            records_by_type[rtype].append(record)

        # Define display order
        type_order = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "SPF", "DMARC"]
        sorted_types = sorted(
            records_by_type.keys(),
            key=lambda x: type_order.index(x) if x in type_order else 99
        )

        if not sorted_types:
            return None

        # Build individual box panels for each record type
        boxes = []
        for rtype in sorted_types:
            recs = records_by_type[rtype]
            is_signed = any(r.is_signed for r in recs)
            color = "green" if is_signed else "grey50"
            signed_text = "[S]" if is_signed else "[U]"
            count = len(recs)

            # Create box content
            box_text = Text()
            box_text.append(f"{rtype}\n", style="bold cyan")
            box_text.append(f"{count} rec{'s' if count > 1 else ''}\n", style="white")
            box_text.append(signed_text, style=color)

            # Wrap in a mini panel
            box = Panel(
                box_text,
                border_style=color,
                width=12,
                padding=(0, 1),
            )
            boxes.append(box)

        # Use Columns for automatic wrapping
        return Columns(boxes, equal=True, expand=False, padding=1)

    def _build_additional_records_boxes(self, target_zone: ZoneInfo) -> Columns | None:
        """Build additional records as dynamic columns that wrap automatically."""
        records = target_zone.additional_records
        if not records:
            return None

        # Group records by type
        records_by_type = {}
        for record in records:
            rtype = record.record_type
            if rtype not in records_by_type:
                records_by_type[rtype] = []
            records_by_type[rtype].append(record)

        # Define display order
        type_order = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "SPF", "DMARC"]
        sorted_types = sorted(
            records_by_type.keys(),
            key=lambda x: type_order.index(x) if x in type_order else 99
        )

        if not sorted_types:
            return None

        # Create a box for each record type
        boxes = []
        for rtype in sorted_types:
            recs = records_by_type[rtype]
            is_signed = any(r.is_signed for r in recs) if len(recs) > 1 else recs[0].is_signed
            color = "green" if is_signed else "grey50"
            signed_text = "[S]" if is_signed else "[U]"

            # Build box as Text
            box = Text()
            box.append(f"┌──────┐\n", style=color)
            box.append(f"│", style=color)
            box.append(f"{rtype[:6].center(6)}", style="bold cyan")
            box.append(f"│\n", style=color)
            box.append(f"│", style=color)
            box.append(f"{signed_text.center(6)}", style=color)
            box.append(f"│\n", style=color)
            box.append(f"└──────┘", style=color)

            boxes.append(box)

        # Use Columns which wraps automatically based on available width
        return Columns(boxes, equal=True, expand=False)

    def _draw_zone_box(self, result: Text, zone: ZoneInfo, indent: str, width: int) -> None:
        """Draw a zone box."""
        status = zone.status
        color = status.color

        # Zone name
        name = zone.name if zone.name != "." else ". (root)"
        if len(name) > width - 4:
            name = name[:width - 7] + "..."

        # Status text
        status_text = f"{status.symbol} {status.value.upper()}"

        # Key info
        if zone.dnskeys:
            ksk_count = sum(1 for k in zone.dnskeys if k.is_ksk)
            zsk_count = sum(1 for k in zone.dnskeys if k.is_zsk)
            key_info = f"KSK:{ksk_count} ZSK:{zsk_count}"
        else:
            key_info = "No DNSKEY"

        # Top border
        result.append(indent)
        result.append(f"{self.BOX_TL}{self.BOX_H * (width - 2)}{self.BOX_TR}\n", style=color)

        # Zone name
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {name.center(width - 4)} ", style="bold white")
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Separator
        result.append(indent)
        result.append(f"{self.BOX_V}{self.BOX_H * (width - 2)}{self.BOX_V}\n", style=color)

        # Status
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {status_text.center(width - 4)} ", style=f"bold {color}")
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Key info
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {key_info.center(width - 4)} ", style="cyan")
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Bottom border
        result.append(indent)
        result.append(f"{self.BOX_BL}{self.BOX_H * (width - 2)}{self.BOX_BR}\n", style=color)

    def _draw_connector(self, result: Text, zone: ZoneInfo, next_zone: ZoneInfo,
                        indent: str, box_width: int, indent_step: int,
                        center_offset: int, zone_idx: int) -> None:
        """Draw the stepped connector between zones."""
        # DS info
        if next_zone.ds_records:
            ds_tags = [str(ds.key_tag) for ds in next_zone.ds_records[:2]]
            if len(next_zone.ds_records) > 2:
                ds_tags.append("...")
            ds_label = f"DS:{','.join(ds_tags)}"
            ds_color = "green" if next_zone.ds_validated else "yellow"
        else:
            ds_label = "No DS"
            ds_color = "red"

        next_indent = " " * (center_offset + (zone_idx + 1) * indent_step)
        connector_col = indent + " " * (box_width // 2)

        # Vertical line down
        result.append(connector_col)
        result.append(self.LINE_V, style=ds_color)
        result.append("\n")

        # Corner and horizontal to next column
        result.append(connector_col)
        result.append(self.CORNER_BL, style=ds_color)
        result.append(self.LINE_H * (indent_step - 1), style=ds_color)
        result.append(self.CORNER_TR, style=ds_color)
        result.append(f" {ds_label}", style=ds_color)
        result.append("\n")

        # Vertical line down to next box
        result.append(next_indent + " " * (box_width // 2))
        result.append(self.LINE_V, style=ds_color)
        result.append("\n")

        # Arrow
        result.append(next_indent + " " * (box_width // 2))
        result.append(self.ARROW_D, style=ds_color)
        result.append("\n")

    def _draw_additional_records(self, result: Text, target_zone: ZoneInfo,
                                  target_indent: int, zone_box_width: int,
                                  record_width: int, record_step: int) -> None:
        """Draw additional records hanging from a horizontal rail below target domain."""
        records = target_zone.additional_records
        if not records:
            return

        # Group records by type
        records_by_type = {}
        for record in records:
            rtype = record.record_type
            if rtype not in records_by_type:
                records_by_type[rtype] = []
            records_by_type[rtype].append(record)

        # Define display order
        type_order = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "SPF", "DMARC"]
        sorted_types = sorted(
            records_by_type.keys(),
            key=lambda x: type_order.index(x) if x in type_order else 99
        )

        num_records = len(sorted_types)
        if num_records == 0:
            return

        # Calculate dimensions
        box_width = 18  # Width of each record box
        box_spacing = 2  # Space between boxes
        total_width = num_records * box_width + (num_records - 1) * box_spacing

        # Center point (below target domain)
        center_col = target_indent + zone_box_width // 2

        # Rail starts left of center, ends right of center
        rail_start = center_col - total_width // 2
        if rail_start < 2:
            rail_start = 2

        # Draw short vertical line down from target domain
        result.append(" " * center_col)
        result.append(self.LINE_V, style="blue")
        result.append("\n")

        # Build the horizontal rail with connection points
        # First, calculate where each box center will be
        box_centers = []
        for i in range(num_records):
            box_center = rail_start + i * (box_width + box_spacing) + box_width // 2
            box_centers.append(box_center)

        # Draw the horizontal rail
        rail_end = box_centers[-1] if box_centers else center_col
        rail_line = ""
        current_pos = 0

        # Pad to rail start
        result.append(" " * rail_start)

        # Draw rail from start to end
        for i in range(rail_start, rail_end + 1):
            if i == center_col:
                # Connection point from vertical line above
                result.append("┴", style="blue")
            elif i in box_centers:
                # Connection point for a box
                result.append("┬", style="blue")
            elif i == rail_start:
                # Left end
                result.append("┌", style="blue")
            elif i == rail_end:
                # Right end
                result.append("┐", style="blue")
            else:
                result.append(self.LINE_H, style="blue")

        result.append("\n")

        # Draw vertical lines down from each connection point
        for box_center in box_centers:
            pass  # We'll draw boxes with their own connectors

        # Draw the vertical connectors line
        result.append(" " * rail_start)
        for i in range(rail_start, rail_end + 1):
            if i in box_centers:
                result.append(self.LINE_V, style="blue")
            else:
                result.append(" ")
        result.append("\n")

        # Draw arrows
        result.append(" " * rail_start)
        for i in range(rail_start, rail_end + 1):
            if i in box_centers:
                result.append(self.ARROW_D, style="blue")
            else:
                result.append(" ")
        result.append("\n")

        # Now draw all boxes side by side
        # Prepare box content for each record type
        box_contents = []
        for rtype in sorted_types:
            recs = records_by_type[rtype]
            if len(recs) > 1:
                value = f"{len(recs)} records"
                is_signed = any(r.is_signed for r in recs)
            else:
                rec = recs[0]
                value = self._format_record_value(rtype, rec.value)
                is_signed = rec.is_signed

            color = "green" if is_signed else "grey50"
            signed_text = "signed" if is_signed else "unsigned"
            box_contents.append((rtype, value, signed_text, is_signed, color))

        # Draw boxes line by line (all boxes at same vertical level)
        # Line 1: Top borders
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_TL}{self.BOX_H * (box_width - 2)}{self.BOX_TR}", style=color)
        result.append("\n")

        # Line 2: Record type
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(self.BOX_V, style=color)
            result.append(f"{rtype.center(box_width - 2)}", style="bold cyan")
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 3: Separator
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_V}{self.BOX_H * (box_width - 2)}{self.BOX_V}", style=color)
        result.append("\n")

        # Line 4: Value
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            display_val = value[:box_width - 4] if len(value) > box_width - 4 else value
            result.append(self.BOX_V, style=color)
            result.append(f"{display_val.center(box_width - 2)}", style="white")
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 5: Signed status
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(self.BOX_V, style=color)
            result.append(f"{signed_text.center(box_width - 2)}", style=color)
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 6: Bottom borders
        result.append(" " * rail_start)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_BL}{self.BOX_H * (box_width - 2)}{self.BOX_BR}", style=color)
        result.append("\n")

    def _format_record_value(self, rtype: str, value: str) -> str:
        """Format a record value for display."""
        if rtype == "SOA":
            if "serial=" in value:
                serial = value.split("serial=")[1].split()[0]
                return f"serial={serial}"
        elif rtype == "NS":
            value = value.split()[0].rstrip('.')
            if len(value) > 16:
                return value[:13] + "..."
        elif rtype in ("A", "AAAA"):
            return value
        elif rtype == "MX":
            parts = value.split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1][:12]}"

        if len(value) > 16:
            return value[:13] + "..."
        return value

    def _draw_record_box(self, result: Text, rtype: str, value: str,
                         signed_text: str, is_signed: bool, indent: str, width: int) -> None:
        """Draw an additional record box."""
        color = "green" if is_signed else "grey50"

        # Truncate value
        if len(value) > width - 4:
            value = value[:width - 7] + "..."

        # Top border
        result.append(indent)
        result.append(f"{self.BOX_TL}{self.BOX_H * (width - 2)}{self.BOX_TR}\n", style=color)

        # Record type
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {rtype.center(width - 4)} ", style="bold cyan")
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Separator
        result.append(indent)
        result.append(f"{self.BOX_V}{self.BOX_H * (width - 2)}{self.BOX_V}\n", style=color)

        # Value
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {value.center(width - 4)} ", style="white")
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Signed status
        result.append(indent)
        result.append(self.BOX_V, style=color)
        result.append(f" {signed_text.center(width - 4)} ", style=color)
        result.append(self.BOX_V, style=color)
        result.append("\n")

        # Bottom border
        result.append(indent)
        result.append(f"{self.BOX_BL}{self.BOX_H * (width - 2)}{self.BOX_BR}\n", style=color)

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
        table.add_column("DS Validation", justify="center")
        table.add_column("Signatures", justify="center")

        for zone in self._chain.zones:
            status = Text(f"{zone.status.symbol} {zone.status.value}", style=zone.status.color)

            if zone.dnskeys:
                ksk = sum(1 for k in zone.dnskeys if k.is_ksk)
                zsk = sum(1 for k in zone.dnskeys if k.is_zsk)
                keys = Text(f"{ksk}K/{zsk}Z", style="cyan")
            else:
                keys = Text("-", style="dim")

            if zone.name == ".":
                ds_val = Text("Trust Anchor", style="magenta")
            elif zone.ds_validated:
                ds_val = Text("Validated", style="green")
            elif zone.ds_records:
                ds_val = Text("Failed", style="red")
            else:
                ds_val = Text("-", style="dim")

            if zone.rrsigs:
                valid_count = sum(1 for r in zone.rrsigs if r.is_valid)
                total = len(zone.rrsigs)
                if valid_count == total:
                    sigs = Text(f"{total} valid", style="green")
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

    def _build_additional_records_table(self) -> Table | None:
        """Build a table showing additional record values."""
        if not self._chain:
            return None

        target_zone = self._chain.target_zone
        if not target_zone or not target_zone.additional_records:
            return None

        table = Table(
            title=None,
            show_header=True,
            header_style="bold",
            border_style="blue",
            padding=(0, 1),
            expand=True,
        )

        table.add_column("Type", style="bold cyan", width=8)
        table.add_column("Name", style="dim")
        table.add_column("Value", style="white")
        table.add_column("TTL", justify="right", style="dim", width=8)
        table.add_column("Signed", justify="center", width=8)

        for record in target_zone.additional_records:
            # Truncate long values (SOA needs more space for serial)
            value = record.value
            max_len = 90 if record.record_type == "SOA" else 50
            if len(value) > max_len:
                value = value[:max_len - 3] + "..."

            signed = Text("Yes", style="green") if record.is_signed else Text("No", style="grey50")

            table.add_row(
                record.record_type,
                record.name.rstrip('.'),
                value,
                str(record.ttl),
                signed,
            )

        return table

    def _build_additional_records_section(self) -> Text:
        """Build a standalone additional records section with horizontal layout."""
        if not self._chain:
            return Text("")

        target_zone = self._chain.target_zone
        if not target_zone or not target_zone.additional_records:
            return Text("")

        records = target_zone.additional_records

        # Group records by type
        records_by_type = {}
        for record in records:
            rtype = record.record_type
            if rtype not in records_by_type:
                records_by_type[rtype] = []
            records_by_type[rtype].append(record)

        # Define display order
        type_order = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "SPF", "DMARC"]
        sorted_types = sorted(
            records_by_type.keys(),
            key=lambda x: type_order.index(x) if x in type_order else 99
        )

        num_records = len(sorted_types)
        if num_records == 0:
            return Text("")

        result = Text()
        box_width = 18
        box_spacing = 2

        # Prepare box content for each record type
        box_contents = []
        for rtype in sorted_types:
            recs = records_by_type[rtype]
            if len(recs) > 1:
                value = f"{len(recs)} records"
                is_signed = any(r.is_signed for r in recs)
            else:
                rec = recs[0]
                value = self._format_record_value(rtype, rec.value)
                is_signed = rec.is_signed

            color = "green" if is_signed else "grey50"
            signed_text = "signed" if is_signed else "unsigned"
            box_contents.append((rtype, value, signed_text, is_signed, color))

        # Calculate total width and centering
        total_width = num_records * box_width + (num_records - 1) * box_spacing
        start_indent = max(2, (80 - total_width) // 2)
        indent = " " * start_indent

        # Draw horizontal rail at top
        result.append(indent)
        rail_width = total_width
        result.append(f"{self.BOX_TL}{self.LINE_H * (rail_width - 2)}{self.BOX_TR}", style="blue")
        result.append("\n")

        # Draw connection points
        result.append(indent)
        for i in range(num_records):
            box_center_offset = i * (box_width + box_spacing) + box_width // 2
            # Pad to this position
            if i == 0:
                result.append(" " * (box_width // 2))
            else:
                result.append(" " * (box_spacing + box_width - 1))
            result.append(self.LINE_V, style="blue")
        result.append("\n")

        # Draw arrows
        result.append(indent)
        for i in range(num_records):
            if i == 0:
                result.append(" " * (box_width // 2))
            else:
                result.append(" " * (box_spacing + box_width - 1))
            result.append(self.ARROW_D, style="blue")
        result.append("\n")

        # Draw boxes line by line
        # Line 1: Top borders
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_TL}{self.BOX_H * (box_width - 2)}{self.BOX_TR}", style=color)
        result.append("\n")

        # Line 2: Record type
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(self.BOX_V, style=color)
            result.append(f"{rtype.center(box_width - 2)}", style="bold cyan")
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 3: Separator
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_V}{self.BOX_H * (box_width - 2)}{self.BOX_V}", style=color)
        result.append("\n")

        # Line 4: Value
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            display_val = value[:box_width - 4] if len(value) > box_width - 4 else value
            result.append(self.BOX_V, style=color)
            result.append(f"{display_val.center(box_width - 2)}", style="white")
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 5: Signed status
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(self.BOX_V, style=color)
            result.append(f"{signed_text.center(box_width - 2)}", style=color)
            result.append(self.BOX_V, style=color)
        result.append("\n")

        # Line 6: Bottom borders
        result.append(indent)
        for i, (rtype, value, signed_text, is_signed, color) in enumerate(box_contents):
            if i > 0:
                result.append(" " * box_spacing)
            result.append(f"{self.BOX_BL}{self.BOX_H * (box_width - 2)}{self.BOX_BR}", style=color)
        result.append("\n")

        return result

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

        # Build waterfall chain (trust chain only)
        chain_viz = self._build_waterfall_chain()

        # Build attached records diagram (dynamic boxes)
        attached_records = self._build_attached_records_diagram()

        # Build summary table
        summary = self._build_summary_table()

        # Build additional records table with values
        additional_table = self._build_additional_records_table()

        # Combine all elements
        elements = [
            header,
            Text(""),
            Text("Trust Chain Flow:", style="bold underline"),
            Text(""),
            chain_viz,
        ]

        # Add attached records diagram if present
        if attached_records:
            elements.extend([
                Text(""),
                Text("Additional Records (attached to target):", style="bold blue"),
                Text(""),
                attached_records,
            ])

        elements.extend([
            Text(""),
            Text("Chain Summary:", style="bold underline"),
            Text(""),
            summary,
        ])

        # Add additional records table if present
        if additional_table:
            elements.extend([
                Text(""),
                Text("Additional Records Values:", style="bold underline"),
                Text(""),
                additional_table,
            ])

        content = Group(*elements)

        return Panel(
            content,
            title="[bold]Chain of Trust - Diagram View[/bold]",
            subtitle=f"[dim]{self._chain.overall_reason}[/dim]",
            border_style=self._chain.overall_status.color,
            padding=(1, 2),
        )
