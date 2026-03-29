"""
core/sniffer.py
---------------
Background packet capture engine.

Architecture
------------
SnifferThread  ← QThread subclass
    · Runs scapy.sniff() in a dedicated OS thread so the Qt event loop
      is never blocked.
    · Emits packet_captured(PacketRecord) via a queued Qt signal so
      UI components can safely consume packets on the main thread.
    · Supports start / stop / pause / resume.

Interface discovery uses socket + netifaces-style probing so it works
correctly even when Scapy's get_if_list() returns [] without root.
"""

from __future__ import annotations
import socket
import struct
import subprocess
import sys
import time
import threading
from typing import Optional

from PySide6.QtCore import QThread, Signal

from scapy.sendrecv import AsyncSniffer

from core.parser import parse_packet, set_capture_start
from core.packet_model import PacketRecord


# ------------------------------------------------------------------ #
# Loopback names to always exclude
# ------------------------------------------------------------------ #
_LOOPBACK = {"lo", "lo0", "localhost", "loopback"}

# macOS priority order — first match wins as default
_MACOS_PREFERRED = ["en0", "en1", "en2", "en3", "en4",
                    "eth0", "eth1", "wlan0", "wlan1"]


# ------------------------------------------------------------------ #
# Interface discovery
# ------------------------------------------------------------------ #

def list_interfaces() -> list[dict]:
    """
    Return a list of interface dicts:
        {"name": str, "addr": str, "active": bool}

    Strategy (works with or without root):
      1. Try the OS-level interface enumeration (socket / ifconfig).
      2. Fall back to a curated static list for the current platform.

    Loopback interfaces are always excluded.
    The list is sorted so the best candidate (active Wi-Fi / Ethernet)
    appears first.
    """
    if sys.platform == "darwin":
        ifaces = _list_macos()
    elif sys.platform.startswith("linux"):
        ifaces = _list_linux()
    elif sys.platform == "win32":
        ifaces = _list_windows()
    else:
        ifaces = _list_fallback()

    # Remove loopback
    ifaces = [i for i in ifaces if i["name"].lower() not in _LOOPBACK]

    # De-duplicate by name, preserve order
    seen: set[str] = set()
    unique = []
    for i in ifaces:
        if i["name"] not in seen:
            seen.add(i["name"])
            unique.append(i)

    # Sort: active interfaces first, then by preferred name list
    def sort_key(i: dict) -> tuple:
        active   = 0 if i.get("active") else 1
        pref_idx = (_MACOS_PREFERRED.index(i["name"])
                    if i["name"] in _MACOS_PREFERRED else 99)
        return (active, pref_idx, i["name"])

    unique.sort(key=sort_key)
    return unique


def get_default_interface() -> str:
    """
    Return the name of the best interface to capture on.
    Prefers the interface that holds the default route.
    """
    # 1. Ask the OS which interface reaches 8.8.8.8
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Find which interface has that IP
        for iface in list_interfaces():
            if iface.get("addr") == local_ip:
                return iface["name"]
    except Exception:
        pass

    # 2. Fall back to first non-loopback interface
    ifaces = list_interfaces()
    if ifaces:
        return ifaces[0]["name"]

    # 3. macOS hard fallback
    if sys.platform == "darwin":
        return "en0"

    return "eth0"


# ------------------------------------------------------------------ #
# Platform-specific enumerators
# ------------------------------------------------------------------ #

def _list_macos() -> list[dict]:
    """Use `ifconfig -l` + `ipconfig getifaddr` — no root needed."""
    ifaces = []
    try:
        output = subprocess.check_output(
            ["ifconfig", "-l"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        names = output.split()
    except Exception:
        names = _MACOS_PREFERRED + ["lo0"]

    for name in names:
        if name.lower() in _LOOPBACK:
            continue
        addr   = _get_ip_macos(name)
        active = bool(addr) and addr != "0.0.0.0"
        ifaces.append({"name": name, "addr": addr, "active": active})
    return ifaces


def _get_ip_macos(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ipconfig", "getifaddr", iface],
            stderr=subprocess.DEVNULL, text=True
        ).strip()
        return out
    except Exception:
        return ""


def _list_linux() -> list[dict]:
    """Read /proc/net/if_inet6 + /proc/net/fib_trie or use `ip addr`."""
    ifaces = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"],
            stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                name = parts[1]
                addr = parts[3].split("/")[0]
                if name.lower() not in _LOOPBACK:
                    ifaces.append({
                        "name": name,
                        "addr": addr,
                        "active": addr != "0.0.0.0",
                    })
    except Exception:
        # Fall back to /sys/class/net
        try:
            import os
            for name in os.listdir("/sys/class/net"):
                if name.lower() not in _LOOPBACK:
                    ifaces.append({"name": name, "addr": "", "active": False})
        except Exception:
            pass
    return ifaces


def _list_windows() -> list[dict]:
    """Use socket.getaddrinfo + a known list."""
    ifaces = []
    try:
        import socket as _s
        hostname = _s.gethostname()
        addrs = _s.getaddrinfo(hostname, None, _s.AF_INET)
        for addr_info in addrs:
            ip = addr_info[4][0]
            if not ip.startswith("127."):
                ifaces.append({"name": ip, "addr": ip, "active": True})
    except Exception:
        pass
    if not ifaces:
        ifaces.append({"name": "Ethernet", "addr": "", "active": False})
    return ifaces


def _list_fallback() -> list[dict]:
    return [
        {"name": "en0",  "addr": "", "active": False},
        {"name": "eth0", "addr": "", "active": False},
    ]


# ------------------------------------------------------------------ #
# Sniffer Thread
# ------------------------------------------------------------------ #

class SnifferThread(QThread):
    """
    Signals
    -------
    packet_captured(PacketRecord)
        Emitted for every captured (and optionally filtered) packet.
    error_occurred(str)
        Emitted if the sniffer crashes.
    stats_updated(int, float)
        Emitted periodically: (total_packets, packets_per_second).
    """

    packet_captured = Signal(object)   # PacketRecord
    error_occurred  = Signal(str)
    stats_updated   = Signal(int, float)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._iface: str = ""
        self._bpf_filter: str = ""
        self._sniffer: Optional[AsyncSniffer] = None
        self._paused: bool = False
        self._seq: int = 0
        self._start_time: float = 0.0
        self._stop_event = threading.Event()
        # Stats
        self._total: int = 0
        self._window_count: int = 0
        self._window_start: float = 0.0

    # ---------------------------------------------------------------- #
    # Public control interface (called from main thread)
    # ---------------------------------------------------------------- #

    def configure(self, iface: str, bpf_filter: str = "") -> None:
        """Set capture interface and optional BPF filter string."""
        self._iface = iface
        self._bpf_filter = bpf_filter

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def stop_capture(self) -> None:
        """Signal the sniffer to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self.quit()
        self.wait(3000)

    # ---------------------------------------------------------------- #
    # QThread.run — executed in the background thread
    # ---------------------------------------------------------------- #

    def run(self) -> None:
        self._stop_event.clear()
        self._paused = False
        self._seq = 0
        self._total = 0
        self._start_time = time.time()
        self._window_start = self._start_time
        self._window_count = 0

        set_capture_start(self._start_time)

        kwargs: dict = {
            "prn": self._on_packet,
            "store": False,       # don't keep packets in memory inside scapy
            "stop_filter": lambda _: self._stop_event.is_set(),
        }
        if self._iface:
            kwargs["iface"] = self._iface
        if self._bpf_filter:
            kwargs["filter"] = self._bpf_filter

        try:
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            # Emit stats every second while running
            while not self._stop_event.is_set():
                time.sleep(1.0)
                self._emit_stats()
            self._sniffer.stop(join=True)
        except PermissionError:
            self.error_occurred.emit(
                "Permission denied — please run as root/administrator."
            )
        except Exception as exc:
            self.error_occurred.emit(str(exc))

    # ---------------------------------------------------------------- #
    # Internal
    # ---------------------------------------------------------------- #

    def _on_packet(self, pkt) -> None:
        if self._paused:
            return
        self._seq += 1
        self._total += 1
        self._window_count += 1
        try:
            record = parse_packet(pkt, self._seq)
            self.packet_captured.emit(record)
        except Exception:
            pass  # never crash the capture thread on a bad packet

    def _emit_stats(self) -> None:
        now = time.time()
        elapsed = now - self._window_start
        pps = self._window_count / elapsed if elapsed > 0 else 0.0
        self._window_count = 0
        self._window_start = now
        self.stats_updated.emit(self._total, pps)
