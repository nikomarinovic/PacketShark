"""
ui/main_window.py
-----------------
Application main window — assembles all UI components into the
Wireshark-style three-panel layout.

Layout
------
  ┌──────────────────────────────────────────────────────┐
  │  Menu Bar                                            │
  ├──────────────────────────────────────────────────────┤
  │  Toolbar: [iface] [Start] [Stop] [Pause] [Filter…]  │
  ├──────────────────────────────────────────────────────┤
  │  PacketTableView  (top, stretches vertically)        │
  ├─────────────────────────┬────────────────────────────┤
  │  DetailsPanel (BL)      │  HexViewer (BR)            │
  └─────────────────────────┴────────────────────────────┘
  │  Status bar                                          │
  └──────────────────────────────────────────────────────┘
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtGui import QAction, QKeySequence, QColor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QToolBar, QComboBox, QPushButton,
    QLineEdit, QLabel, QStatusBar, QFileDialog,
    QMessageBox, QApplication
)

from core.sniffer import SnifferThread, list_interfaces, get_default_interface
from core.packet_model import PacketRecord
from core.filters import compile_filter

from ui.packet_table import PacketTableView
from ui.details_panel import DetailsPanel
from ui.hex_viewer import HexViewer


class MainWindow(QMainWindow):
    """
    Top-level application window.
    Owns the SnifferThread and routes its signals to the UI components.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PyShark — Network Packet Analyzer")
        self.resize(1400, 900)

        # ── State ────────────────────────────────────────────────── #
        self._sniffer: Optional[SnifferThread] = None
        self._capturing = False
        self._paused    = False
        self._total_captured = 0

        # ── Build UI ─────────────────────────────────────────────── #
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        # ── Filter debounce timer ─────────────────────────────────── #
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(300)   # 300 ms debounce
        self._filter_timer.timeout.connect(self._apply_filter)

        self._refresh_ifaces()
        self._update_controls()

    # ================================================================ #
    # UI construction
    # ================================================================ #

    def _build_menu(self) -> None:
        bar = self.menuBar()

        # File
        file_menu = bar.addMenu("&File")
        act_open = QAction("&Open PCAP…", self)
        act_open.setShortcut(QKeySequence("Ctrl+O"))
        act_open.triggered.connect(self._open_pcap)
        file_menu.addAction(act_open)

        act_save = QAction("&Save Capture…", self)
        act_save.setShortcut(QKeySequence("Ctrl+S"))
        act_save.triggered.connect(self._save_pcap)
        file_menu.addAction(act_save)

        file_menu.addSeparator()
        act_quit = QAction("&Quit", self)
        act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        act_quit.triggered.connect(QApplication.quit)
        file_menu.addAction(act_quit)

        # Capture
        cap_menu = bar.addMenu("&Capture")
        act_start = QAction("&Start", self)
        act_start.setShortcut(QKeySequence("F5"))
        act_start.triggered.connect(self._start_capture)
        cap_menu.addAction(act_start)

        act_stop = QAction("S&top", self)
        act_stop.setShortcut(QKeySequence("F6"))
        act_stop.triggered.connect(self._stop_capture)
        cap_menu.addAction(act_stop)

        act_clear = QAction("&Clear", self)
        act_clear.setShortcut(QKeySequence("Ctrl+L"))
        act_clear.triggered.connect(self._clear_packets)
        cap_menu.addAction(act_clear)

        cap_menu.addSeparator()
        act_refresh = QAction("&Refresh Interfaces", self)
        act_refresh.triggered.connect(self._refresh_ifaces)
        cap_menu.addAction(act_refresh)

        # View
        view_menu = bar.addMenu("&View")
        act_scroll = QAction("Auto-Scroll", self, checkable=True)
        act_scroll.setChecked(True)
        act_scroll.triggered.connect(self._toggle_autoscroll)
        self._act_scroll = act_scroll
        view_menu.addAction(act_scroll)

        # Help
        help_menu = bar.addMenu("&Help")
        act_about = QAction("&About", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main Toolbar", self)
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(tb)

        # Interface label + combo
        iface_label = QLabel("Interface:")
        tb.addWidget(iface_label)

        self._iface_combo = QComboBox()
        self._iface_combo.setToolTip("Select network interface to capture on")
        tb.addWidget(self._iface_combo)

        tb.addSeparator()

        # Start
        self._btn_start = QPushButton("▶  Start")
        self._btn_start.setObjectName("btn_start")
        self._btn_start.setToolTip("Start packet capture  [F5]")
        self._btn_start.clicked.connect(self._start_capture)
        tb.addWidget(self._btn_start)

        # Stop
        self._btn_stop = QPushButton("■  Stop")
        self._btn_stop.setObjectName("btn_stop")
        self._btn_stop.setToolTip("Stop packet capture  [F6]")
        self._btn_stop.clicked.connect(self._stop_capture)
        tb.addWidget(self._btn_stop)

        # Pause
        self._btn_pause = QPushButton("⏸  Pause")
        self._btn_pause.setObjectName("btn_clear")
        self._btn_pause.setToolTip("Pause / Resume capture")
        self._btn_pause.setCheckable(True)
        self._btn_pause.clicked.connect(self._toggle_pause)
        tb.addWidget(self._btn_pause)

        # Clear
        self._btn_clear = QPushButton("✕  Clear")
        self._btn_clear.setObjectName("btn_clear")
        self._btn_clear.setToolTip("Clear packet list  [Ctrl+L]")
        self._btn_clear.clicked.connect(self._clear_packets)
        tb.addWidget(self._btn_clear)

        tb.addSeparator()

        # Filter
        filter_label = QLabel("Filter:")
        tb.addWidget(filter_label)

        self._filter_edit = QLineEdit()
        self._filter_edit.setObjectName("filter_bar")
        self._filter_edit.setPlaceholderText("tcp  |  udp  |  ip.src == 192.168.1.1  |  port 80  ...")
        self._filter_edit.setMinimumWidth(340)
        self._filter_edit.textChanged.connect(self._on_filter_text_changed)
        self._filter_edit.returnPressed.connect(self._apply_filter)
        tb.addWidget(self._filter_edit)

        # Filter status indicator
        self._filter_status = QLabel("")
        self._filter_status.setObjectName("status_indicator")
        tb.addWidget(self._filter_status)

    def _build_central(self) -> None:
        """
        Three-panel layout:
        top  = PacketTableView
        BL   = DetailsPanel
        BR   = HexViewer
        """
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Outer vertical splitter: table (top) vs bottom row
        outer_splitter = QSplitter(Qt.Vertical)
        outer_splitter.setHandleWidth(4)

        # ── Packet table ──────────────────────────────────────────── #
        self._table = PacketTableView()
        self._table.packet_selected.connect(self._on_packet_selected)
        self._table.packet_model().row_count_changed.connect(self._on_row_count_changed)
        outer_splitter.addWidget(self._table)

        # ── Bottom row: details + hex ─────────────────────────────── #
        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.setHandleWidth(4)

        self._details = DetailsPanel()
        bottom_splitter.addWidget(self._details)

        self._hex = HexViewer()
        bottom_splitter.addWidget(self._hex)

        bottom_splitter.setSizes([600, 600])
        outer_splitter.addWidget(bottom_splitter)

        outer_splitter.setSizes([500, 300])
        root_layout.addWidget(outer_splitter)

        # Auto-scroll timer (runs every 100 ms when capturing)
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setInterval(100)
        self._scroll_timer.timeout.connect(self._auto_scroll)
        self._autoscroll = True

    def _build_statusbar(self) -> None:
        sb = QStatusBar(self)
        self.setStatusBar(sb)

        self._lbl_status  = QLabel("Ready")
        self._lbl_packets = QLabel("Packets: 0")
        self._lbl_pps     = QLabel("0 p/s")
        self._lbl_filter  = QLabel("")

        for lbl in (self._lbl_status, self._lbl_packets,
                    self._lbl_pps, self._lbl_filter):
            sb.addPermanentWidget(lbl)

    # ================================================================ #
    # Interface management
    # ================================================================ #

    def _refresh_ifaces(self) -> None:
        self._iface_combo.clear()
        ifaces = list_interfaces()

        if not ifaces:
            # Hard fallback — let user type manually
            self._iface_combo.setEditable(True)
            self._iface_combo.addItem("en0", "en0")
            self._iface_combo.setCurrentText("en0")
            self._lbl_status.setText("⚠  No interfaces detected — defaulting to en0")
            self._lbl_status.setStyleSheet("color: #fbbf24; font-weight: 600;")
            return

        self._iface_combo.setEditable(False)
        default = get_default_interface()
        default_index = 0

        for i, iface in enumerate(ifaces):
            name = iface["name"]
            addr = iface.get("addr", "")
            active = iface.get("active", False)

            # Build a readable label
            if addr:
                label = f"{name}  —  {addr}"
            else:
                label = name

            # Mark active interfaces
            if active:
                label = "● " + label   # filled dot = has IP / active
            else:
                label = "○ " + label   # empty dot = no IP / inactive

            self._iface_combo.addItem(label, name)

            if name == default:
                default_index = i

        self._iface_combo.setCurrentIndex(default_index)
        selected = ifaces[default_index]
        self._lbl_status.setText(
            f"Ready — default interface: {selected['name']}"
            + (f"  ({selected['addr']})" if selected.get('addr') else "")
        )
        self._lbl_status.setStyleSheet("color: #71717a;")

    # ================================================================ #
    # Capture control
    # ================================================================ #

    def _start_capture(self) -> None:
        if self._capturing:
            return

        iface = self._iface_combo.currentData() or ""
        if not iface and self._iface_combo.count() == 0:
            QMessageBox.warning(self, "No Interface",
                                "No network interfaces found.\n"
                                "Please run PyShark with sufficient privileges.")
            return

        self._capturing = True
        self._paused    = False
        self._btn_pause.setChecked(False)

        self._sniffer = SnifferThread(self)
        self._sniffer.configure(iface)
        self._sniffer.packet_captured.connect(self._table.add_packet)
        self._sniffer.packet_captured.connect(self._on_new_packet_for_count)
        self._sniffer.error_occurred.connect(self._on_sniffer_error)
        self._sniffer.stats_updated.connect(self._on_stats_updated)
        self._sniffer.start()

        if self._autoscroll:
            self._scroll_timer.start()

        self._lbl_status.setText(f"● Capturing on  {iface or 'all interfaces'}")
        self._lbl_status.setStyleSheet("color: #4ade80; font-weight: 700;")
        self._update_controls()

    def _stop_capture(self) -> None:
        if not self._capturing:
            return
        self._capturing = False
        self._scroll_timer.stop()

        if self._sniffer:
            self._sniffer.stop_capture()
            self._sniffer = None

        self._lbl_status.setText("■  Capture stopped")
        self._lbl_status.setStyleSheet("color: #f87171; font-weight: 700;")
        self._update_controls()

    def _toggle_pause(self, checked: bool) -> None:
        self._paused = checked
        if self._sniffer:
            if checked:
                self._sniffer.pause()
                self._lbl_status.setText("⏸  Capture paused")
                self._lbl_status.setStyleSheet("color: #fbbf24; font-weight: 700;")
            else:
                self._sniffer.resume()
                iface = self._iface_combo.currentData() or "all interfaces"
                self._lbl_status.setText(f"● Capturing on  {iface}")
                self._lbl_status.setStyleSheet("color: #4ade80; font-weight: 700;")
        self._btn_pause.setText("▶  Resume" if checked else "⏸  Pause")

    def _clear_packets(self) -> None:
        self._table.clear_packets()
        self._details.clear()
        self._hex.clear()
        self._total_captured = 0
        self._lbl_packets.setText("Packets: 0")

    # ================================================================ #
    # Filter
    # ================================================================ #

    def _on_filter_text_changed(self, text: str) -> None:
        # Reset style while typing
        self._filter_edit.setStyleSheet("")
        self._filter_status.setText("")
        self._filter_timer.start()

    def _apply_filter(self) -> None:
        text = self._filter_edit.text().strip()
        if not text:
            self._table.apply_filter(None)
            self._filter_status.setText("")
            self._filter_edit.setStyleSheet("")
            self._lbl_filter.setText("")
            return
        try:
            f = compile_filter(text)
            self._table.apply_filter(f)
            self._filter_edit.setStyleSheet(
                "border: 1px solid #22c55e; color: #86efac;"
            )
            self._filter_status.setText("✓")
            self._filter_status.setStyleSheet("color: #4ade80; font-weight: 700;")
            self._lbl_filter.setText(f"Filter: {text}")
        except ValueError as e:
            self._filter_edit.setStyleSheet(
                "border: 1px solid #ef4444; color: #fca5a5;"
            )
            self._filter_status.setText("✗")
            self._filter_status.setStyleSheet("color: #ef4444; font-weight: 700;")
            self._lbl_filter.setText(f"Filter error: {e}")

    # ================================================================ #
    # PCAP I/O
    # ================================================================ #

    def _open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP File", "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if not path:
            return
        self._stop_capture()
        self._clear_packets()
        self._lbl_status.setText(f"Loading  {Path(path).name} …")
        self._lbl_status.setStyleSheet("color: #60a5fa; font-weight: 600;")

        from scapy.utils import rdpcap
        from core.parser import set_capture_start
        import time as _time

        try:
            packets = rdpcap(path)
            if packets:
                set_capture_start(float(packets[0].time))
            for i, pkt in enumerate(packets, 1):
                from core.parser import parse_packet
                rec = parse_packet(pkt, i)
                self._table.add_packet(rec)
            self._lbl_status.setText(
                f"Loaded  {len(packets)} packets  from  {Path(path).name}"
            )
            self._lbl_status.setStyleSheet("color: #60a5fa; font-weight: 600;")
            self._lbl_packets.setText(f"Packets: {len(packets)}")
        except Exception as e:
            QMessageBox.critical(self, "Error Opening PCAP", str(e))
            self._lbl_status.setText("Error loading file")
            self._lbl_status.setStyleSheet("color: #f87171;")

    def _save_pcap(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture", "",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        if not path:
            return

        from scapy.utils import wrpcap
        model = self._table.packet_model()
        packets = [
            model.get_record(i)._scapy_pkt
            for i in range(model.total_captured())
            if model.get_record(i) and model.get_record(i)._scapy_pkt
        ]
        if not packets:
            QMessageBox.information(self, "Save", "No packets to save.")
            return
        try:
            wrpcap(path, packets)
            QMessageBox.information(
                self, "Saved",
                f"Saved {len(packets)} packets to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    # ================================================================ #
    # Slots
    # ================================================================ #

    @Slot(object)
    def _on_packet_selected(self, record: PacketRecord) -> None:
        self._details.display_packet(record)
        self._hex.display_packet(record)

    @Slot(object)
    def _on_new_packet_for_count(self, _: PacketRecord) -> None:
        self._total_captured += 1

    @Slot(int)
    def _on_row_count_changed(self, count: int) -> None:
        total = self._table.packet_model().total_captured()
        if self._filter_edit.text().strip():
            self._lbl_packets.setText(f"Displaying {count} / {total} packets")
        else:
            self._lbl_packets.setText(f"Packets: {count}")

    @Slot(int, float)
    def _on_stats_updated(self, total: int, pps: float) -> None:
        self._lbl_pps.setText(f"{pps:.1f} p/s")

    @Slot(str)
    def _on_sniffer_error(self, msg: str) -> None:
        self._capturing = False
        self._scroll_timer.stop()
        self._update_controls()
        self._lbl_status.setText(f"Error: {msg}")
        self._lbl_status.setStyleSheet("color: #f87171; font-weight: 700;")
        QMessageBox.critical(
            self, "Capture Error",
            f"{msg}\n\nTip: On Linux/macOS run with  sudo.\n"
            "On Windows, install Npcap."
        )

    def _auto_scroll(self) -> None:
        if self._autoscroll and not self._paused:
            self._table.scroll_to_bottom_if_needed()

    def _toggle_autoscroll(self, checked: bool) -> None:
        self._autoscroll = checked
        if not checked:
            self._scroll_timer.stop()
        elif self._capturing:
            self._scroll_timer.start()

    # ================================================================ #
    # Control state
    # ================================================================ #

    def _update_controls(self) -> None:
        self._btn_start.setEnabled(not self._capturing)
        self._btn_stop.setEnabled(self._capturing)
        self._btn_pause.setEnabled(self._capturing)
        self._iface_combo.setEnabled(not self._capturing)

    # ================================================================ #
    # About
    # ================================================================ #

    def _show_about(self) -> None:
        QMessageBox.about(
            self, "About PyShark",
            "<h3>PyShark</h3>"
            "<p>A professional network packet analyzer built with:"
            "<ul>"
            "<li><b>Python 3.11+</b></li>"
            "<li><b>PySide6</b> (Qt 6)</li>"
            "<li><b>Scapy</b></li>"
            "</ul>"
            "<p>Inspired by Wireshark. Built for learning and analysis.</p>"
        )

    # ================================================================ #
    # Window close
    # ================================================================ #

    def closeEvent(self, event) -> None:
        self._stop_capture()
        event.accept()
