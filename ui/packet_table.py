"""
ui/packet_table.py
------------------
High-performance packet list using Qt's Model/View architecture.

PacketTableModel  — QAbstractTableModel backed by a list of PacketRecords.
                    Supports virtual / lazy rendering (only visible rows
                    are ever queried by Qt), so thousands of rows are fast.

PacketTableView   — QTableView subclass with column sizing, alternating
                    row colors, and protocol-based row tinting.

The model accumulates packets in _rows.  When a display filter is active,
_visible stores the filtered subset (indices into _rows).
"""

from __future__ import annotations
from typing import Optional

from PySide6.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel,
    Signal, Slot
)
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QTableView, QAbstractItemView, QHeaderView

from core.packet_model import PacketRecord
from core.filters import CompiledFilter


# ------------------------------------------------------------------ #
# Column definitions
# ------------------------------------------------------------------ #
COLUMNS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
COL_NO   = 0
COL_TIME = 1
COL_SRC  = 2
COL_DST  = 3
COL_PROT = 4
COL_LEN  = 5
COL_INFO = 6

# Protocol accent colors (text color — rows use a dimmer bg)
_PROTO_FG: dict[str, str] = {
    "TCP":    "#4ade80",   # green
    "UDP":    "#60a5fa",   # blue
    "ICMP":   "#c084fc",   # purple
    "ICMPv6": "#e879f9",   # fuchsia
    "DNS":    "#fbbf24",   # amber
    "HTTP":   "#fb923c",   # orange
    "HTTPS":  "#f97316",
    "ARP":    "#818cf8",   # indigo
    "IPv6":   "#38bdf8",   # sky
    "IPv4":   "#6ee7b7",
}


# ------------------------------------------------------------------ #
# Model
# ------------------------------------------------------------------ #

class PacketTableModel(QAbstractTableModel):
    """
    Stores all PacketRecords; exposes either the full list or a
    filtered subset depending on whether a CompiledFilter is set.
    """

    row_count_changed = Signal(int)   # total visible rows

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[PacketRecord] = []
        self._visible: list[int] = []   # indices into _rows when filtered
        self._filter: Optional[CompiledFilter] = None
        self._font = QFont("JetBrains Mono, Cascadia Code, Fira Code, Consolas", 11)

    # ---------------------------------------------------------------- #
    # Qt interface
    # ---------------------------------------------------------------- #

    def rowCount(self, parent=QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._visible) if self._filter else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        rec = self._get_record(index.row())
        if rec is None:
            return None

        col = index.column()

        if role == Qt.DisplayRole:
            return self._display(rec, col)

        if role == Qt.ForegroundRole:
            fg = _PROTO_FG.get(rec.protocol)
            if fg:
                return QColor(fg)
            return QColor("#a1a1aa")

        if role == Qt.BackgroundRole:
            bg = rec.row_color
            if bg:
                return QColor(bg)
            return None

        if role == Qt.FontRole:
            return self._font

        if role == Qt.TextAlignmentRole:
            if col in (COL_NO, COL_LEN):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        # Store the actual PacketRecord as UserData for the detail panel
        if role == Qt.UserRole:
            return rec

        return None

    # ---------------------------------------------------------------- #
    # Data mutation
    # ---------------------------------------------------------------- #

    @Slot(object)
    def append_packet(self, record: PacketRecord) -> None:
        """Append one packet; skip if it doesn't match current filter."""
        idx = len(self._rows)
        self._rows.append(record)

        if self._filter:
            if self._filter.matches(record):
                vis_row = len(self._visible)
                self.beginInsertRows(QModelIndex(), vis_row, vis_row)
                self._visible.append(idx)
                self.endInsertRows()
                self.row_count_changed.emit(len(self._visible))
            # else: packet captured but hidden by filter — don't insert
        else:
            row = idx
            self.beginInsertRows(QModelIndex(), row, row)
            self.endInsertRows()
            self.row_count_changed.emit(len(self._rows))

    def set_filter(self, f: Optional[CompiledFilter]) -> None:
        """Apply or clear a display filter.  Rebuilds visible index."""
        self.beginResetModel()
        self._filter = f
        if f:
            self._visible = [i for i, r in enumerate(self._rows) if f.matches(r)]
        else:
            self._visible = []
        self.endResetModel()
        count = len(self._visible) if f else len(self._rows)
        self.row_count_changed.emit(count)

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._visible.clear()
        self.endResetModel()
        self.row_count_changed.emit(0)

    def get_record(self, model_row: int) -> Optional[PacketRecord]:
        return self._get_record(model_row)

    def total_captured(self) -> int:
        return len(self._rows)

    # ---------------------------------------------------------------- #
    # Helpers
    # ---------------------------------------------------------------- #

    def _get_record(self, model_row: int) -> Optional[PacketRecord]:
        try:
            if self._filter:
                return self._rows[self._visible[model_row]]
            return self._rows[model_row]
        except IndexError:
            return None

    @staticmethod
    def _display(rec: PacketRecord, col: int) -> str:
        if col == COL_NO:   return str(rec.no)
        if col == COL_TIME: return f"{rec.time:.6f}"
        if col == COL_SRC:  return rec.src
        if col == COL_DST:  return rec.dst
        if col == COL_PROT: return rec.protocol
        if col == COL_LEN:  return str(rec.length)
        if col == COL_INFO: return rec.info
        return ""


# ------------------------------------------------------------------ #
# View
# ------------------------------------------------------------------ #

class PacketTableView(QTableView):
    """
    QTableView tuned for packet display:
    · Stretches Info column
    · Fixed row heights for density
    · Emits packet_selected(PacketRecord) when a row is clicked
    """

    packet_selected = Signal(object)   # PacketRecord

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._model = PacketTableModel(self)
        self.setModel(self._model)
        self._setup_ui()
        self.selectionModel().currentRowChanged.connect(self._on_row_changed)

    def _setup_ui(self) -> None:
        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(COL_NO,   QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(COL_TIME, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(COL_SRC,  QHeaderView.Interactive)
        hdr.setSectionResizeMode(COL_DST,  QHeaderView.Interactive)
        hdr.setSectionResizeMode(COL_PROT, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(COL_LEN,  QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(COL_INFO, QHeaderView.Stretch)
        hdr.setDefaultSectionSize(120)
        hdr.setMinimumSectionSize(50)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(22)

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setCornerButtonEnabled(False)
        self.horizontalHeader().setHighlightSections(False)
        self.setColumnWidth(COL_SRC, 160)
        self.setColumnWidth(COL_DST, 160)

    # ---------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------- #

    @Slot(object)
    def add_packet(self, record: PacketRecord) -> None:
        self._model.append_packet(record)

    def apply_filter(self, f) -> None:
        self._model.set_filter(f)

    def clear_packets(self) -> None:
        self._model.clear()

    def packet_model(self) -> PacketTableModel:
        return self._model

    def scroll_to_bottom_if_needed(self) -> None:
        """Auto-scroll only if user hasn't scrolled up manually."""
        sb = self.verticalScrollBar()
        if sb.value() >= sb.maximum() - 50:
            self.scrollToBottom()

    # ---------------------------------------------------------------- #
    # Slots
    # ---------------------------------------------------------------- #

    def _on_row_changed(self, current: QModelIndex, _prev: QModelIndex) -> None:
        rec = self._model.get_record(current.row())
        if rec:
            self.packet_selected.emit(rec)
