"""
ui/details_panel.py
-------------------
Protocol detail tree panel (bottom-left).

Shows an expandable tree of all Scapy layers and their fields
when the user clicks a packet in the table.
"""

from __future__ import annotations
from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QFont, QBrush, QIcon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel
)

from core.packet_model import PacketRecord
from core.parser import build_detail_tree


# Layer header colors
_LAYER_COLORS: dict[str, str] = {
    "Ether":          "#818cf8",
    "IP":             "#4ade80",
    "IPv6":           "#38bdf8",
    "TCP":            "#34d399",
    "UDP":            "#60a5fa",
    "ICMP":           "#c084fc",
    "ICMPv6":         "#e879f9",
    "DNS":            "#fbbf24",
    "HTTPRequest":    "#fb923c",
    "HTTPResponse":   "#f97316",
    "ARP":            "#818cf8",
    "Raw":            "#71717a",
    "Padding":        "#52525b",
}

_DEFAULT_LAYER_COLOR = "#94a3b8"


class DetailsPanel(QWidget):
    """
    Displays the layered protocol breakdown of a selected packet.
    Each layer is a top-level tree item; its fields are children.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Panel title bar
        title = QLabel("PACKET DETAILS")
        title.setObjectName("panel_title")
        layout.addWidget(title)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setColumnCount(2)
        self._tree.setIndentation(18)
        self._tree.setAnimated(True)
        self._tree.setUniformRowHeights(True)
        self._tree.header().setStretchLastSection(True)
        self._tree.setAlternatingRowColors(False)

        # Font for field values
        self._val_font = QFont(
            "JetBrains Mono, Cascadia Code, Fira Code, Consolas", 11
        )

        layout.addWidget(self._tree)

    # ---------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------- #

    @Slot(object)
    def display_packet(self, record: Optional[PacketRecord]) -> None:
        self._tree.clear()
        if record is None or record._scapy_pkt is None:
            return

        layers = build_detail_tree(record._scapy_pkt)
        for layer_info in layers:
            layer_name = layer_info["layer"]
            fields = layer_info["fields"]

            # Top-level: layer name
            layer_item = QTreeWidgetItem([layer_name, ""])
            color = _LAYER_COLORS.get(layer_name, _DEFAULT_LAYER_COLOR)
            layer_item.setForeground(0, QBrush(QColor(color)))
            layer_item.setFont(0, self._make_bold_font())
            layer_item.setExpanded(True)

            # Children: field = value
            for fname, fval in fields:
                child = QTreeWidgetItem([fname, fval])
                child.setForeground(0, QBrush(QColor("#71717a")))
                child.setForeground(1, QBrush(QColor("#d4d4d8")))
                child.setFont(1, self._val_font)
                layer_item.addChild(child)

            self._tree.addTopLevelItem(layer_item)

        self._tree.resizeColumnToContents(0)

    def clear(self) -> None:
        self._tree.clear()

    # ---------------------------------------------------------------- #
    # Helpers
    # ---------------------------------------------------------------- #

    def _make_bold_font(self) -> QFont:
        f = QFont("JetBrains Mono, Cascadia Code, Fira Code, Consolas", 11)
        f.setBold(True)
        return f
