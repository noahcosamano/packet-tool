# Packet Crafter

**A Python-based packet crafting and network testing tool built with Scapy.**  
Supports TCP, UDP, and ICMP protocols, with features like IP spoofing, and flag control.

> ⚠️ This tool is intended **strictly for educational and lab use**. Do not use it on unauthorized networks.

---

## Features

- Craft custom packets at Layer 2 and Layer 3
- Send packets with:
  - Custom source/destination IPs
  - Spoofed ports
  - TCP flags (`F`, `S`, `A`, `P`, `R`, `U`)
  - Optional destination MAC address (Ethernet layer)
- Supports:
  - **TCP**
  - **UDP**
  - **ICMP**
- Send-only or send-and-receive modes
- Logs sent packets and responses to a `.csv` file
- Optional hashing of sensitive data (e.g., IP, MAC)
- Input validation for IP addresses, ports, flags, and MACs

---

## Installation

> Requires Python 3.10+ and `scapy`

```bash
git clone https://github.com/yourusername/packet-crafter.git
cd packet-crafter
