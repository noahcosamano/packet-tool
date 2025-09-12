"""
This module provides input validation functions for IPv4 addresses, MAC addresses,
ports, protocols, TCP flags, ARP operation codes, payloads, and packet counts.

These functions are used throughout the packet crafting application to ensure
all user inputs meet expected formats and protocol rules.

Author: Noah Cosamano
"""

import ipaddress
import re

VALID_MAC = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
VALID_TCP_FLAGS = {"f", "s", "r", "p", "a", "u"}
VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}


def validate_ipv6(ipv6: str) -> str:
    """
    Validates an IPv6 address string.

    Args:
        ipv4 (str): IPv6 address to validate.

    Returns:
        str: The validated IPv6 address.

    Raises:
        ValueError: If the IPv6 address is invalid.
    """
    try:
        ipaddress.IPv6Address(ipv6)
        return ipv6
    except ValueError:
        raise ValueError(f" Error: Invalid IPv6 address: {ipv6}")


def validate_ipv4(ipv4: str) -> str:
    """
    Validates an IPv4 address string.

    Args:
        ipv4 (str): IPv4 address to validate.

    Returns:
        str: The validated IPv4 address.

    Raises:
        ValueError: If the IPv4 address is invalid.
    """
    try:
        ipaddress.IPv4Address(ipv4)
        return ipv4
    except ValueError:
        raise ValueError(f" Error: Invalid IPv4 address: {ipv4}")


def validate_mac(
    mac: str, protocol: str | None = None, arp_op: int | None = None
) -> str:
    """
    Validates a MAC address string.

    Args:
        mac (str): MAC address to validate.
        protocol (str, optional): Protocol context ("arp", "tcp", etc.).
        arp_op (int, optional): ARP operation (1 for request, 2 for reply).

    Returns:
        str: The validated MAC address.

    Raises:
        ValueError: If MAC is invalid or not allowed for given ARP op.
    """
    if mac is not None and (protocol == "arp") and arp_op == 1:
        raise ValueError(" Error: ARP op #1 does not support destination MAC")

    if not isinstance(mac, str) or not VALID_MAC.match(mac):
        raise ValueError(f" Error: Invalid MAC address: {mac}")

    return mac


def validate_port(port: int, protocol: str) -> int:
    """
    Validates a port number, ensuring it's allowed for the given protocol.

    Args:
        port (int): Port number to validate.
        protocol (str): Associated protocol (e.g., "tcp", "udp").

    Returns:
        int: The validated port number.

    Raises:
        ValueError: If the port is invalid or not supported for the protocol.
    """
    try:
        port = int(port)
    except Exception:
        raise ValueError(f" Error: Invalid port: {port}")
    if port is not None and (protocol.lower() in ("arp", "icmp")):
        raise ValueError(f" Error: {protocol.upper()} does not support ports")
    if not 1 <= port <= 65535:
        raise ValueError(f" Error: Invalid port: {port}")
    return port


def validate_tcp_flags(flags: list | str | None, protocol: str) -> list[str] | None:
    """
    Validates TCP flags for a TCP packet.

    Args:
        flags (list|str|None): Flags to validate (e.g., "S" or ["S", "A"]).
        protocol (str): Protocol context (must be "tcp").

    Returns:
        list[str]: List of lowercase TCP flags.

    Raises:
        ValueError: If flags are invalid or not allowed for non-TCP protocols.
    """
    if flags is not None and protocol.lower() != "tcp":
        raise ValueError(" Error: Only TCP accepts flags")
    if not isinstance(flags, (str, list)):
        raise ValueError(f" Error: Invalid TCP flag(s): {flags}")
    flag_list = list(flags) if isinstance(flags, str) else flags
    for flag in flag_list:
        if flag.lower() not in VALID_TCP_FLAGS:
            raise ValueError(f" Error: Invalid TCP flag(s): {flag}")
    return flag_list


def validate_protocol(protocol: str) -> str:
    """
    Validates a protocol name (TCP, ICMP, UDP, ARP).

    Args:
        protocol (str): Protocol name to validate.

    Returns:
        str: Lowercase version of the protocol.

    Raises:
        ValueError: If protocol is unsupported.
    """
    if protocol.upper() not in VALID_PROTOCOLS:
        raise ValueError(" Error: Unsupported packet protocol")
    return protocol.lower()


def validate_arp_op(arp_op: int | None, protocol: str) -> int | None:
    """
    Validates an ARP operation code (1 or 2).

    Args:
        arp_op (int|None): ARP operation code.
        protocol (str): Protocol context (must be "arp").

    Returns:
        int: The validated ARP op code.

    Raises:
        ValueError: If protocol is not ARP or op code is invalid.
    """
    if protocol == "arp":
        if int(arp_op) < 1 or int(arp_op) > 2:
            raise ValueError(" Error: ARP operator must be 1 or 2")
        return arp_op
    raise ValueError(" Error: only ARP accepts ARP operators")


def validate_payload(payload) -> str | None:
    """
    Validates the payload field, ensuring it can be converted to a string.

    Args:
        payload (any): Payload to validate.

    Returns:
        str|None: Stringified payload or None.

    Raises:
        ValueError: If payload cannot be converted to a string.
    """
    if payload:
        try:
            payload = str(payload)
            return payload
        except Exception:
            raise ValueError(" Error: Invalid payload")
    return None


def validate_num_pkts(num_pkts: int) -> int:
    """
    Validates the number of packets to send.

    Args:
        num_pkts (int): Number of packets (should be between 1 and 500).

    Returns:
        int: The validated number of packets.

    Raises:
        ValueError: If number is not an integer or out of range.
    """
    try:
        num_pkts = int(num_pkts)
        if not 500 >= num_pkts >= 1:
            raise ValueError(" Error: Number of packets must be between 1 and 500")
        return num_pkts
    except Exception:
        raise ValueError(f" Error: Invalid number of packets: {num_pkts}")
