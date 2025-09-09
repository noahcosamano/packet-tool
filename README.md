# PacketCrafter

**Author:** Noah Cosamano

---

## Overview

**PacketCrafter** is a command-line based packet crafting tool designed for educational purposes. It supports crafting and sending packets using **TCP**, **UDP**, **ICMP**, and **ARP** protocols. Users can specify detailed packet parameters such as destination/source IP addresses, MAC addresses, ports, TCP flags, payloads, and ARP operations. 

All packets sent and responses received are logged securely in a local SQL database, with sensitive data (IP addresses, MAC addresses, payloads) hashed for privacy.

---

## ⚠️ Important Disclaimer

This program is intended **only for educational use** within controlled environments such as private lab networks or virtual labs. It **must NOT** be used for unauthorized activities like probing, flooding, scanning, or any form of unauthorized network access. 

Misuse of this tool on production or public networks can be illegal and unethical.

---

## Features

- Interactive CLI prompt for packet creation.
- Support for protocols: TCP, UDP, ICMP, ARP.
- Specify destination/source IPv4 and MAC addresses.
- Customize ports, TCP flags, payloads, ARP operation types.
- Send multiple packets in a single command (up to 500 packets).
- Options to send packets normally or send and wait for replies.
- Logs all packet details and responses into a local SQLite database with hashed sensitive data.

---

## Installation

### Requirements

- Python 3.7+
- [Scapy](https://scapy.net/) library
- SQLite3 (usually included in Python standard library)

Install Scapy via pip:

```bash
pip install scapy


