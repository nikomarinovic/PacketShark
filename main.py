"""
main.py
-------
PyShark — Network Packet Analyzer
Entry point: bootstraps the Qt application, loads the theme,
and launches the main window.

Usage
-----
    sudo python main.py          # Linux / macOS (root required for raw capture)
    python main.py               # Windows with Npcap installed
"""

from __future__ import annotations
import sys
import os
from pathlib import Path

# ── Make sure project root is on sys.path ────────────────────────── #
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPalette, QColor


def _load_stylesheet(app: QApplication) -> None:
    """Read and apply the dark QSS theme."""
    qss_path = ROOT / "styles" / "dark_theme.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))
    else:
        print(f"[warn] Stylesheet not found: {qss_path}")


def _configure_palette(app: QApplication) -> None:
    """
    Set a base dark palette so native widgets that don't read QSS
    (e.g. title bar on some platforms) inherit dark colors.
    """
    palette = QPalette()
    dark = QColor("#0f0f11")
    palette.setColor(QPalette.Window,          dark)
    palette.setColor(QPalette.WindowText,      QColor("#d4d4d8"))
    palette.setColor(QPalette.Base,            QColor("#09090b"))
    palette.setColor(QPalette.AlternateBase,   QColor("#0f0f11"))
    palette.setColor(QPalette.Text,            QColor("#d4d4d8"))
    palette.setColor(QPalette.Button,          QColor("#27272a"))
    palette.setColor(QPalette.ButtonText,      QColor("#e4e4e7"))
    palette.setColor(QPalette.Highlight,       QColor("#1d4ed8"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.Link,            QColor("#60a5fa"))
    palette.setColor(QPalette.ToolTipBase,     QColor("#18181b"))
    palette.setColor(QPalette.ToolTipText,     QColor("#d4d4d8"))
    app.setPalette(palette)


def main() -> int:
    # High-DPI support
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("PyShark")
    app.setOrganizationName("PyShark")
    app.setApplicationVersion("1.0.0")

    # Use Fusion style as a consistent cross-platform base
    app.setStyle("Fusion")

    _configure_palette(app)
    _load_stylesheet(app)

    # Default application font
    font = QFont()
    font.setFamily("JetBrains Mono, Cascadia Code, Segoe UI, sans-serif")
    font.setPointSize(10)
    app.setFont(font)

    # Lazy import after Qt is running to avoid Scapy warnings before window
    from ui.main_window import MainWindow
    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
