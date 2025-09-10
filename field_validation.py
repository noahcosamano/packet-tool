"""
This program is the logical file for the main command line interface file.
Please see "packet_crafter_CLI.py" for full program.

Author: Noah Cosamano
"""

import ipaddress
import re
import sqlite3
import hashlib
from datetime import datetime
from scapy.layers.inet import TCP, IP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.sendrecv import send, sendp, sr1, srp1


VALID_MAC = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
VALID_TCP_FLAGS = {"f", "s", "r", "p", "a", "u"}
VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}


def validate_ip(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise ValueError(f"\tError: Invalid IP address: {ip}")


def validate_mac(
    mac: str, protocol: str | None = None, arp_op: int | None = None
) -> str:
    if mac is not None and (protocol == "arp") and arp_op == 1:
        raise ValueError("\tError: ARP op #1 does not support destination MAC")

    if not isinstance(mac, str) or not VALID_MAC.match(mac):
        raise ValueError(f"\tError: Invalid MAC address: {mac}")

    return mac


def validate_port(port: int, protocol: str) -> int:
    try:
        port = int(port)
    except Exception:
        raise ValueError(f"\tError: Invalid port: {port}")
    if port is not None and (protocol.lower() in ("arp", "icmp")):
        raise ValueError(f"\tError: {protocol.upper()} does not support ports")
    if not 1 <= port <= 65535:
        raise ValueError(f"\tError: Invalid port: {port}")
    return port


def validate_tcp_flags(flags: list | str | None, protocol: str) -> list[str] | None:
    if flags is not None and protocol.lower() != "tcp":
        raise ValueError(f"\tError: {protocol.upper()} does not support flags")
    if not isinstance(flags, (str, list)):
        raise ValueError(f"\tError: Invalid TCP flags: {flags}")
    flag_list = list(flags) if isinstance(flags, str) else flags
    for flag in flag_list:
        if flag.lower() not in VALID_TCP_FLAGS:
            raise ValueError(f"\tError: Invalid TCP flag: {flag}")
    return flag_list


def validate_protocol(protocol: str) -> str:
    if protocol.upper() not in VALID_PROTOCOLS:
        raise ValueError("\tError: Invalid protocol")
    return protocol.lower()


def validate_arp_op(arp_op: int | None, protocol: str) -> int | None:
    if protocol == "arp":
        if int(arp_op) < 1 or int(arp_op) > 2:
            raise ValueError("\tError: ARP operator must be 1 or 2")
        return arp_op
    raise ValueError("\tError: only ARP supports ARP operators")


def validate_payload(payload) -> str | None:
    if payload:
        try:
            payload = str(payload)
            return payload
        except Exception:
            raise ValueError("\tError: Invalid payload")
    return None


def validate_num_pkts(num_pkts: int) -> int:
    try:
        num_pkts = int(num_pkts)
        if not 500 >= num_pkts >= 1:
            raise ValueError("\tError: Number of packets must be between 1 and 500")
        return num_pkts
    except Exception:
        raise ValueError(f"\tError: Invalid number of packets: {num_pkts}")

