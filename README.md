<h1 align="center">
  <img src="public/logo.png" alt="PacketShark Logo" width="96" />
  <br />
  PacketShark
</h1>

<p align="center">
  Professional network packet analyzer built with Python, PySide6, and Scapy.
</p>

---

## What is PacketShark?

**PacketShark is a desktop packet analyzer inspired by Wireshark, built entirely in Python:**

- Real-time packet capture from any network interface
- Supports Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, and HTTP
- Wireshark-style three-panel layout — packet list, protocol tree, hex viewer
- Live display filter engine with Wireshark-style syntax
- Protocol color coding for instant visual identification
- Save and load `.pcap` files
- Dark theme, clean modern UI

**`Runs locally on your machine. No cloud. No telemetry.`**

---

## Requirements

Before installing, make sure you have the following:

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | System Python on macOS is too old — see below |
| PySide6 | 6.6+ | Qt6 GUI framework |
| Scapy | 2.5+ | Packet capture engine |
| libpcap | any | Usually pre-installed on macOS/Linux |
| Root / Admin | — | Required for raw packet capture |

---

## Installation

### macOS

**1. Install Homebrew** (if you don't have it):
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**2. Install Python 3.11:**
```bash
brew install python@3.11
```

**3. Install libpcap:**
```bash
brew install libpcap
```

**4. Install Python dependencies:**
```bash
/opt/homebrew/bin/pip3.11 install PySide6 scapy
```

**5. Run PacketShark** (`sudo` is required for raw packet capture):
```bash
sudo /opt/homebrew/bin/python3.11 main.py
```

---

### Linux (Ubuntu / Debian)

**1. Install Python and libpcap:**
```bash
sudo apt update
sudo apt install python3 python3-pip libpcap-dev
```

**2. Install Python dependencies:**
```bash
pip3 install PySide6 scapy
```

**3. Run PacketShark:**
```bash
sudo python3 main.py
```

---

### Linux (Arch / Manjaro)

```bash
sudo pacman -S python python-pip libpcap
pip install PySide6 scapy
sudo python main.py
```

---

### Windows

**1. Install Python 3.11+** from [python.org](https://python.org) — check **"Add to PATH"** during setup.

**2. Install [Npcap](https://npcap.com/)** — required for packet capture on Windows. Choose **"WinPcap API-compatible mode"** during installation.

**3. Install Python dependencies:**
```bash
pip install PySide6 scapy
```

**4. Run as Administrator** — right-click your terminal and choose "Run as Administrator", then:
```bash
python main.py
```

---

## How It Works

1. **Select your interface** — PacketShark automatically detects and pre-selects your active Wi-Fi or Ethernet interface. You can switch interfaces from the dropdown.
2. **Click Start** — packets begin streaming in real time into the packet list.
3. **Click a packet** — the protocol tree and hex viewer update instantly with full layer breakdown.
4. **Type a filter** — the packet list updates dynamically as you type.
5. **Save your capture** — use File → Save Capture to export a `.pcap` file compatible with Wireshark.

> [!TIP]
> Use `sudo` on macOS/Linux every time — without it Scapy cannot open raw sockets and the interface list will appear empty.

---

## Filter Syntax

PacketShark supports a Wireshark-inspired display filter language:

```
tcp                         # show only TCP packets
udp                         # show only UDP packets
dns                         # show only DNS packets
icmp                        # show only ICMP packets
http                        # show only HTTP packets
ip.src == 192.168.1.1       # filter by source IP
ip.dst == 8.8.8.8           # filter by destination IP
port 80                     # filter by port number
port == 443                 # HTTPS traffic only
len > 500                   # packets larger than 500 bytes
tcp && ip.src == 10.0.0.1   # combine with AND
tcp || udp                  # combine with OR
!icmp                       # exclude a protocol
```

---

## Features

- **Live Capture** — real-time packet streaming with Start / Stop / Pause controls
- **Smart Interface Detection** — automatically finds and pre-selects your active network interface
- **Protocol Tree** — expandable layer-by-layer breakdown of every packet
- **Hex Viewer** — raw byte dump with hex + ASCII columns and syntax highlighting
- **Display Filters** — dynamic filtering without stopping capture
- **Color Coding** — TCP green · UDP blue · ICMP purple · DNS amber
- **PCAP Support** — save captures and load existing `.pcap` / `.pcapng` files
- **Packet Counter** — live packet count and packets-per-second display
- **Keyboard Shortcuts** — `F5` start · `F6` stop · `Ctrl+O` open · `Ctrl+S` save · `Ctrl+L` clear

---

## Project Structure

```
PacketShark/
│
├── main.py                  # Entry point — Qt bootstrap and theme loader
├── requirements.txt
│
├── core/
│   ├── sniffer.py           # Background capture thread (QThread + AsyncSniffer)
│   ├── parser.py            # Scapy → PacketRecord translation
│   ├── packet_model.py      # PacketRecord dataclass
│   └── filters.py           # Recursive-descent display filter engine
│
├── ui/
│   ├── main_window.py       # Main window, toolbar, menus, splitter layout
│   ├── packet_table.py      # PacketTableModel + PacketTableView (Qt MVC)
│   ├── details_panel.py     # Protocol tree widget
│   └── hex_viewer.py        # Hex + ASCII byte dump viewer
│
└── styles/
    └── dark_theme.qss       # Full dark theme stylesheet
```

---

## Permissions & Privacy

PacketShark captures raw network packets directly from your hardware. This requires elevated privileges:

> [!WARNING]
> Always run PacketShark with `sudo` on macOS/Linux, or as Administrator on Windows. Without this, the interface list will be empty and capture will fail.

> [!NOTE]
> PacketShark captures **all traffic** on the selected interface, including unencrypted data. Only use it on networks you own or have explicit permission to monitor.

All capture data stays entirely on your local machine. PacketShark makes no network connections of its own.

---

<h3 align="center">
PacketShark does not accept feature implementations via pull requests. Feature requests and bug reports are welcome through GitHub issues.
</h3>

---

<p align="center">
  © 2026 Niko Marinović. All rights reserved.
</p>
