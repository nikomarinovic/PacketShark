"""
core/parser.py
--------------
Translates a raw Scapy packet into a PacketRecord.

All Scapy knowledge is concentrated here so the rest of the application
can stay Scapy-free.
"""

from __future__ import annotations
import time
from typing import Optional

from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR, DNSRR

try:
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    _HAS_HTTP = True
except ImportError:
    _HAS_HTTP = False

from core.packet_model import PacketRecord

# Capture-start timestamp — set by the sniffer before the first packet
_capture_start: float = 0.0


def set_capture_start(ts: float) -> None:
    global _capture_start
    _capture_start = ts


def parse_packet(pkt: Packet, seq: int) -> PacketRecord:
    """
    Convert a Scapy packet into a PacketRecord.

    Parameters
    ----------
    pkt : Scapy Packet
    seq : int  — 1-based sequence number

    Returns
    -------
    PacketRecord
    """
    raw = bytes(pkt)
    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
    rel_time = ts - _capture_start if _capture_start else 0.0

    src, dst, proto, info = _extract_fields(pkt)

    return PacketRecord(
        no=seq,
        time=rel_time,
        src=src,
        dst=dst,
        protocol=proto,
        length=len(raw),
        info=info,
        raw_bytes=raw,
        _scapy_pkt=pkt,
    )


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _extract_fields(pkt: Packet) -> tuple[str, str, str, str]:
    """Return (src, dst, protocol, info) strings."""

    # ── HTTP ──────────────────────────────────────────────────────── #
    if _HAS_HTTP:
        if pkt.haslayer(HTTPRequest):
            method  = _safe_decode(pkt[HTTPRequest].Method)
            path    = _safe_decode(pkt[HTTPRequest].Path)
            host    = _safe_decode(pkt[HTTPRequest].Host)
            src, dst = _ip_addrs(pkt)
            return src, dst, "HTTP", f"{method} {host}{path}"
        if pkt.haslayer(HTTPResponse):
            status = _safe_decode(pkt[HTTPResponse].Status_Code)
            reason = _safe_decode(pkt[HTTPResponse].Reason_Phrase)
            src, dst = _ip_addrs(pkt)
            return src, dst, "HTTP", f"HTTP {status} {reason}"

    # ── DNS ───────────────────────────────────────────────────────── #
    if pkt.haslayer(DNS):
        src, dst = _ip_addrs(pkt)
        dns = pkt[DNS]
        qr   = "Response" if dns.qr else "Query"
        name = ""
        if dns.qr == 0 and dns.qd:                          # query
            name = _safe_decode(dns.qd.qname)
        elif dns.qr == 1 and dns.an:                         # answer
            name = _safe_decode(dns.an.rrname)
        return src, dst, "DNS", f"DNS {qr}: {name}"

    # ── ICMPv6 ────────────────────────────────────────────────────── #
    if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
        src, dst = _ip6_addrs(pkt)
        kind = "Echo Request" if pkt.haslayer(ICMPv6EchoRequest) else "Echo Reply"
        return src, dst, "ICMPv6", f"ICMPv6 {kind}"

    # ── ICMP ──────────────────────────────────────────────────────── #
    if pkt.haslayer(ICMP):
        src, dst = _ip_addrs(pkt)
        icmp = pkt[ICMP]
        type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded"}
        kind = type_map.get(icmp.type, f"Type {icmp.type}")
        return src, dst, "ICMP", f"ICMP {kind} id={icmp.id if hasattr(icmp,'id') else ''}"

    # ── TCP ───────────────────────────────────────────────────────── #
    if pkt.haslayer(TCP):
        src, dst = _ip_addrs(pkt)
        tcp = pkt[TCP]
        flags = _tcp_flags(tcp.flags)
        return (f"{src}:{tcp.sport}", f"{dst}:{tcp.dport}",
                "TCP", f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}")

    # ── UDP ───────────────────────────────────────────────────────── #
    if pkt.haslayer(UDP):
        src, dst = _ip_addrs(pkt)
        udp = pkt[UDP]
        return (f"{src}:{udp.sport}", f"{dst}:{udp.dport}",
                "UDP", f"{udp.sport} → {udp.dport} Len={udp.len}")

    # ── ARP ───────────────────────────────────────────────────────── #
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        info = (f"Who has {arp.pdst}? Tell {arp.psrc}"
                if arp.op == 1
                else f"{arp.psrc} is at {arp.hwsrc}")
        return arp.psrc, arp.pdst, "ARP", f"ARP {op}: {info}"

    # ── IPv6 ──────────────────────────────────────────────────────── #
    if pkt.haslayer(IPv6):
        src, dst = _ip6_addrs(pkt)
        return src, dst, "IPv6", f"IPv6 nh={pkt[IPv6].nh}"

    # ── IPv4 ──────────────────────────────────────────────────────── #
    if pkt.haslayer(IP):
        src, dst = _ip_addrs(pkt)
        return src, dst, "IPv4", f"IPv4 proto={pkt[IP].proto}"

    # ── Ethernet fallback ─────────────────────────────────────────── #
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return eth.src, eth.dst, "Ethernet", f"Ethertype=0x{eth.type:04x}"

    return "??", "??", "Unknown", pkt.summary()


def _ip_addrs(pkt: Packet) -> tuple[str, str]:
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "??", "??"


def _ip6_addrs(pkt: Packet) -> tuple[str, str]:
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return "??", "??"


def _tcp_flags(flags) -> str:
    names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
             0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    val = int(flags)
    return " ".join(v for k, v in names.items() if val & k) or str(flags)


def _safe_decode(val) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace").strip(".")
    return str(val).strip(".")


# ------------------------------------------------------------------ #
# Packet detail tree builder
# ------------------------------------------------------------------ #

def build_detail_tree(pkt: Packet) -> list[dict]:
    """
    Walk each Scapy layer and return a list of
    {'layer': str, 'fields': [(name, value), ...]} dicts.
    Used by the details panel TreeWidget.
    """
    layers = []
    current = pkt
    while current:
        layer_name = current.__class__.__name__
        fields = []
        for fname, fval in current.fields.items():
            if isinstance(fval, bytes):
                display = fval.hex(" ") if len(fval) <= 32 else f"{fval[:32].hex(' ')}…"
            else:
                display = str(fval)
            fields.append((fname, display))
        layers.append({"layer": layer_name, "fields": fields})
        # Move to payload, stop at Raw if nothing recognizable
        if current.payload and current.payload.__class__.__name__ != "NoPayload":
            current = current.payload
        else:
            break
    return layers
