"""
ui/hex_viewer.py
----------------
Hex + ASCII byte dump panel (bottom-right).

Renders the raw packet bytes in the classic two-column layout:
  offset | hex octets (16 per line) | printable ASCII

Uses QPlainTextEdit with a fixed-width monospace font for best
alignment and performance.  Syntax-highlighting is done with
a QSyntaxHighlighter subclass.
"""

from __future__ import annotations
from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import (
    QColor, QFont, QTextCharFormat, QSyntaxHighlighter, QTextDocument
)
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QLabel

from core.packet_model import PacketRecord

_BYTES_PER_LINE = 16


class HexViewer(QWidget):
    """
    Displays a hex + ASCII dump of raw packet bytes.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()
        self._highlighter = HexHighlighter(self._edit.document())

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        title = QLabel("HEX VIEWER")
        title.setObjectName("panel_title")
        layout.addWidget(title)

        self._edit = QPlainTextEdit()
        self._edit.setReadOnly(True)
        self._edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = QFont(
            "JetBrains Mono, Cascadia Code, Fira Code, Consolas", 11
        )
        self._edit.setFont(font)
        self._edit.setMaximumBlockCount(0)  # no limit
        layout.addWidget(self._edit)

    # ---------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------- #

    @Slot(object)
    def display_packet(self, record: Optional[PacketRecord]) -> None:
        if record is None:
            self._edit.clear()
            return
        self._edit.setPlainText(_format_hex(record.raw_bytes))

    def clear(self) -> None:
        self._edit.clear()


# ------------------------------------------------------------------ #
# Formatting
# ------------------------------------------------------------------ #

def _format_hex(data: bytes) -> str:
    """Convert raw bytes to a hex + ASCII dump string."""
    lines: list[str] = []
    for i in range(0, len(data), _BYTES_PER_LINE):
        chunk = data[i: i + _BYTES_PER_LINE]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to fixed width
        hex_part = hex_part.ljust(_BYTES_PER_LINE * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{i:06x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Syntax Highlighter
# ------------------------------------------------------------------ #

class HexHighlighter(QSyntaxHighlighter):
    """
    Colours the hex dump for readability:
    · Offset  → dim cyan
    · Hex     → light grey
    · ASCII   → soft green
    · Zero bytes → extra dim
    """

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)
        self._fmt_offset = self._fmt("#22d3ee", bold=False)   # cyan
        self._fmt_hex    = self._fmt("#d4d4d8")
        self._fmt_ascii  = self._fmt("#4ade80")
        self._fmt_zero   = self._fmt("#3f3f46")
        self._fmt_sep    = self._fmt("#27272a")

    def highlightBlock(self, text: str) -> None:
        if not text.strip():
            return

        # Offset (first 6 chars)
        self.setFormat(0, 6, self._fmt_offset)

        # Two spaces separator
        self.setFormat(6, 2, self._fmt_sep)

        # Hex section: positions 8 .. 8 + 16*3 - 1 = 55
        hex_start = 8
        hex_end   = hex_start + _BYTES_PER_LINE * 3 - 1
        for i, pos in enumerate(range(hex_start, min(hex_end, len(text)), 3)):
            byte_str = text[pos: pos + 2]
            fmt = self._fmt_zero if byte_str == "00" else self._fmt_hex
            self.setFormat(pos, 2, fmt)

        # Two spaces separator
        self.setFormat(hex_end, 2, self._fmt_sep)

        # ASCII section
        ascii_start = hex_end + 2
        if ascii_start < len(text):
            self.setFormat(ascii_start, len(text) - ascii_start, self._fmt_ascii)

    @staticmethod
    def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(700)
        return fmt
