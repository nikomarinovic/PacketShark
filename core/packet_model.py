"""
core/packet_model.py
--------------------
Data model for a captured packet.
Lightweight dataclass — no Scapy object stored directly in the model so
the table/model layer never needs to import Scapy.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketRecord:
    """
    Immutable record that represents one captured packet.
    Stored in the central packet list and displayed in the table.
    """
    # Sequence number (1-based, assigned by the sniffer)
    no: int

    # Relative capture time in seconds since capture started
    time: float

    # Layer-3 addresses (may be MAC if ARP / non-IP)
    src: str
    dst: str

    # Highest-level protocol detected (e.g. "TCP", "DNS", "HTTP")
    protocol: str

    # Total wire length in bytes
    length: int

    # One-line human-readable summary
    info: str

    # Raw bytes of the complete frame
    raw_bytes: bytes

    # Scapy packet kept for the detail / hex view; NOT used for the table
    # Use Optional so we don't force a Scapy import everywhere
    _scapy_pkt: Optional[object] = field(default=None, repr=False)

    # ------------------------------------------------------------------ #
    # Protocol colour mapping used by the table delegate
    # ------------------------------------------------------------------ #
    PROTOCOL_COLORS: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        # Avoid mutable class-level dict to keep the dataclass picklable
        object.__setattr__(self, "PROTOCOL_COLORS", {
            "TCP":   "#14532d",   # dark green
            "UDP":   "#172554",   # dark blue
            "ICMP":  "#2e1065",   # dark purple
            "ICMPv6": "#3b0764",
            "DNS":   "#422006",   # dark amber
            "HTTP":  "#1c1917",
            "HTTPS": "#1c1917",
            "ARP":   "#1e1b4b",
            "IPv6":  "#0c2340",
        })

    @property
    def row_color(self) -> Optional[str]:
        """Return a hex bg color for this protocol, or None for default."""
        return self.PROTOCOL_COLORS.get(self.protocol)
