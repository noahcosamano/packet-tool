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
    """
    Validates an IPv4 address using the ipaddress module.

    Args:
        ip (str): IPv4 address to validate.

    Raises:
        ValueError: If IPv4 address is invalid.

    Returns:
        str: The validated IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise ValueError(f"\tError: Invalid IP address: {ip}")


def validate_mac(
    mac: str, protocol: str | None = None, arp_op: int | None = None
) -> str:
    """
    Validates MAC address against ARP operator if given, and if it conforms to
    standard MAC address format with isinstance and checking regular expression.

    Args:
        mac (str): MAC address to validate.
        protocol (str | None: Protocol to check with. Defaults to None.
        arp_op (int | None): ARP operator to check with. Defaults to None.

    Raises:
        ValueError: If MAC address is not string or not matching standard format.
        ValueError: If protocol is ARP and ARP operator is 1.

    Returns:
        str: The validated MAC address
    """
    if mac is not None and (protocol == "arp") and arp_op == 1:
        raise ValueError("\tError: ARP op #1 does not support destination MAC")

    if not isinstance(mac, str) or not VALID_MAC.match(mac):
        raise ValueError(f"\tError: Invalid MAC address: {mac}")

    return mac


def validate_port(port: int, protocol: str) -> int:
    """
    Validates a port number for a given protocol.

    Args:
        port (int): The port number to validate.
        protocol (str): The protocol name (e.g., 'tcp', 'udp', 'arp', 'icmp').

    Raises:
        ValueError: If the port is not an integer.
        ValueError: If the protocol does not support ports (e.g., ARP or ICMP).
        ValueError: If the port number is outside the valid range (1-65535).

    Returns:
        int: The validated port number.
    """
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
    """
    Validates TCP flags for the given protocol.

    Args:
        flags (list | str | None): TCP flags as a list or string to validate.
        protocol (str): Protocol name to check compatibility with TCP flags.

    Raises:
        ValueError: If the protocol does not support TCP flags.
        ValueError: If flags are not a string or list.
        ValueError: If any flag is not a valid TCP flag.

    Returns:
        list[str] | None: List of validated TCP flags or None if no flags provided.
    """
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
    """
    Validates if the given protocol is supported.

    Args:
        protocol (str): Protocol name to validate.

    Raises:
        ValueError: If the protocol is not in the list of valid protocols.

    Returns:
        str: The validated protocol in lowercase.
    """
    if protocol.upper() not in VALID_PROTOCOLS:
        raise ValueError(f"\tError: Invalid protocol: {protocol}")
    return protocol.lower()


def validate_arp_op(arp_op: int | None, protocol: str) -> int | None:
    """
    Validates the ARP operation code if the protocol is ARP.

    Args:
        arp_op (int | None): ARP operation code to validate.
        protocol (str): Protocol name to check for ARP.

    Raises:
        ValueError: If protocol is not 'arp'.
        ValueError: If arp_op is not 1 (request) or 2 (reply).

    Returns:
        int | None: The validated ARP operation code.
    """
    if protocol == "arp":
        if int(arp_op) < 1 or int(arp_op) > 2:
            raise ValueError("\tError: ARP operator must be 1 or 2")
        return arp_op
    raise ValueError("\tError: only ARP supports ARP operators")


def validate_payload(payload) -> str | None:
    """
    Validates and converts the payload to a string if it exists.

    Args:
        payload: The payload data to validate.

    Raises:
        ValueError: If the payload cannot be converted to a string.

    Returns:
        str | None: The validated payload as a string, or None if no payload is provided.
    """
    if payload:
        try:
            payload = str(payload)
            return payload
        except Exception:
            raise ValueError("\tError: Invalid payload")
    return None


def validate_num_pkts(num_pkts: int) -> int:
    """
    Validates that the number of packets is an integer between 1 and 500.

    Args:
        num_pkts (int): The number of packets to validate.

    Raises:
        ValueError: If `num_pkts` is not an integer or not within the valid range.

    Returns:
        int: The validated number of packets.
    """
    try:
        num_pkts = int(num_pkts)
        if not 500 >= num_pkts >= 1:
            raise ValueError("\tError: Number of packets must be between 1 and 500")
        return num_pkts
    except Exception:
        raise ValueError(f"\tError: Invalid number of packets: {num_pkts}")


class Packet:
    """
    Represents a network packet with attributes for various protocols and validation.

    This class encapsulates all necessary fields for crafting network packets, including
    IP addresses, MAC addresses, ports, protocol type, flags, payload, number of packets,
    and ARP operation codes. It validates all inputs upon initialization to ensure correctness
    and compatibility based on the specified protocol.

    Attributes:
        dst_ip (str): Destination IP address (required).
        src_ip (str | None): Source IP address (optional).
        dst_mac (str | None): Destination MAC address (optional).
        src_mac (str | None): Source MAC address (optional).
        protocol (str): Protocol type (e.g., 'tcp', 'udp', 'icmp', 'arp') (required).
        dst_port (int | None): Destination port (required for TCP and UDP).
        src_port (int | None): Source port (optional).
        flags (list[str] | None): TCP flags (only supported if protocol is TCP).
        payload (str | None): Payload data as string (not supported for ARP).
        num_pkts (int): Number of packets to send (default is 1, between 1 and 500).
        arp_op (int | None): ARP operation code (1 for request, 2 for reply) (only for ARP).

    Raises:
        ValueError: If required fields are missing or invalid, or if protocol-specific
                    restrictions are violated.

    Example:
        >>> pkt = Packet(
                dst_ip="192.168.1.1",
                protocol="tcp",
                dst_port=80,
                flags="s",
                src_ip="192.168.1.2",
                src_port=12345,
                payload="Hello",
                num_pkts=5
            )
    """

    __slots__ = [
        "dst_ip",
        "dst_mac",
        "protocol",
        "dst_port",
        "flags",
        "src_port",
        "src_ip",
        "src_mac",
        "payload",
        "num_pkts",
        "arp_op",
    ]

    def __init__(
        self,
        dst_ip: str = None,
        protocol: str = None,
        dst_port: int = None,
        flags: str | list = None,
        dst_mac: str = None,
        src_port: int = None,
        src_ip: str = None,
        src_mac: str = None,
        payload: str = None,
        num_pkts: int = 1,
        arp_op: int = 1,
    ):

        if not dst_ip:
            raise ValueError("\tError: Destination IP required")

        if not protocol:
            raise ValueError("\tError: Protocol required")

        if not dst_port and protocol in ("tcp", "udp"):
            raise ValueError("\tError: Destination port required for TCP and UDP")

        self.protocol = protocol.lower()

        self.dst_ip = validate_ip(dst_ip) if dst_ip else None
        self.src_ip = validate_ip(src_ip) if src_ip else None
        self.dst_mac = validate_mac(dst_mac, protocol, arp_op) if dst_mac else None
        self.src_mac = validate_mac(src_mac) if src_mac else None
        self.src_port = validate_port(src_port, protocol) if src_port else None
        self.dst_port = validate_port(dst_port, protocol) if dst_port else None
        self.payload = validate_payload(payload) if payload else None
        self.num_pkts = validate_num_pkts(num_pkts) if num_pkts else 1

        if flags is not None:
            if protocol == "tcp":
                self.flags = validate_tcp_flags(flags, protocol)
            else:
                raise ValueError(f"\tError: {protocol.upper()} does not support flags")
        else:
            self.flags = flags

        if protocol == "arp":
            if payload:
                raise ValueError("\tError: ARP does not support payloads")
            if flags:
                raise ValueError("\tError: ARP does not support flags")
            if not (src_ip and src_mac and dst_ip):
                raise ValueError(
                    "\tError: ARP requires source IP, source MAC, and destination IP"
                )

            self.arp_op = validate_arp_op(arp_op, protocol)

            if arp_op == 1:
                if dst_mac is not None:
                    raise ValueError(
                        "\tError: ARP op #1 does not support destination MAC"
                    )
                self.dst_mac = "ff:ff:ff:ff:ff:ff"
            elif arp_op == 2 and not self.dst_mac:
                raise ValueError("\tError: ARP replies require destination MAC")
            elif arp_op not in [1, 2]:
                raise ValueError("\tError: Invalid ARP operator")

        else:
            self.arp_op = None

        if protocol in ("tcp", "udp") and not dst_port:
            raise ValueError(f"\tError: {protocol.upper()} requires a destination port")
        if protocol not in ("tcp", "udp", "icmp", "arp"):
            raise ValueError("\tError: Unsupported protocol")

    def create_packet(self):
        """
        Constructs and returns a Scapy packet based on the instance's attributes.

        Supports ARP, TCP, UDP, and ICMP protocols. If MAC addresses are provided,
        the packet is encapsulated within an Ethernet frame. If a payload is set,
        it is added as a Raw layer.

        Returns:
            scapy.packet.Packet: The constructed packet ready for sending.

        Raises:
            None explicitly, but assumes all instance attributes are validated prior.

        Notes:
            - For ARP packets, sets operation, source and destination MAC/IP as needed.
            - For TCP/UDP, sets source/destination ports and TCP flags if applicable.
            - If no source IP is provided, the packet uses only the destination IP.
        """

        ether = Ether()
        payload = Raw(load=self.payload.encode()) if self.payload else None

        if self.protocol == "arp":
            arp = ARP(
                op=self.arp_op, hwsrc=self.src_mac, psrc=self.src_ip, pdst=self.dst_ip
            )
            if self.dst_mac:
                ether.dst = self.dst_mac
                arp.hwdst = self.dst_mac
            pkt = ether / arp

        else:
            ip = (
                IP(dst=self.dst_ip, src=self.src_ip)
                if self.src_ip
                else IP(dst=self.dst_ip)
            )
            if self.protocol == "tcp":
                tcp = TCP(dport=self.dst_port, sport=self.src_port or 12345)
                if self.flags:
                    tcp.flags = "".join(self.flags).upper()
                layer4 = tcp
            elif self.protocol == "udp":
                layer4 = UDP(dport=self.dst_port, sport=self.src_port or 12345)
            elif self.protocol == "icmp":
                layer4 = ICMP()
            pkt = ip / layer4
            if self.dst_mac or self.src_mac:
                if self.dst_mac:
                    ether.dst = self.dst_mac
                if self.src_mac:
                    ether.src = self.src_mac
                pkt = ether / pkt

        return pkt / payload if payload else pkt

    def send_packet(self):
        """
        Sends the constructed packet multiple times based on the num_pkts attribute.

        Uses `sendp` (layer 2) if either source or destination MAC address is specified,
        otherwise uses `send` (layer 3). After sending each packet, logs the packet details.

        Returns:
            None
        """

        pkt = self.create_packet()

        for _ in range(self.num_pkts):
            if self.dst_mac or self.src_mac:
                sendp(pkt, verbose=0)
            else:
                send(pkt, verbose=0)

            log_packet(self)

    def send_receive_packet(self):
        """
        Sends the constructed packet and waits for a single response for each packet sent.

        Uses `srp1` (layer 2) if either source or destination MAC address is specified,
        otherwise uses `sr1` (layer 3). Sends packets `num_pkts` times, logs each packet
        and its response summary, and prints the response summary or a no-response message.

        Returns:
            The last response packet received, or None if no response was received.
        """

        pkt = self.create_packet()

        for _ in range(self.num_pkts):

            if self.dst_mac or self.src_mac:
                response = srp1(pkt, timeout=3, verbose=0)
            else:
                response = sr1(pkt, timeout=3, verbose=0)

            log_packet(
                self,
                response_summary=response.summary() if response else "\tNo response",
            )

            if response:
                print(f"\tReceived: {response.summary()}")
            else:
                print("\tNo response")

        return response

    def __str__(self):
        return (
            f"\tProtocol: {self.protocol.upper()}, DST IP: {self.dst_ip}, DST MAC: {self.dst_mac}, "
            f"\tDST Port: {self.dst_port}, SRC IP: {self.src_ip}, SRC MAC: {self.src_mac}, "
            f"\tSRC Port: {self.src_port}, Flags: {self.flags}, Payload: {self.payload}, Packets: "
            f"{self.num_pkts}"
        )


def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def log_packet(packet: Packet, response_summary: str | None = None, anonymize=True):
    """
    Logs packet details and an optional response summary into a SQLite database.

    Creates a table named 'packet_history' if it doesn't exist, then inserts
    the packet's metadata along with an optional response summary. Optionally
    anonymizes sensitive fields by hashing.

    Args:
        packet (Packet): The packet object containing attributes like IPs, MACs,
                         protocol, ports, flags, payload, and ARP operation.
        response_summary (str | None, optional): An optional summary or response
                         related to the packet to be logged. Defaults to None.
        anonymize (bool, optional): Whether to anonymize sensitive data fields
                         (IP addresses, MAC addresses, payload) by hashing.
                         Defaults to True.

    Returns:
        None
    """
    conn = sqlite3.connect("packet_history.sqlite")
    c = conn.cursor()

    c.execute(
        """ 
        CREATE TABLE IF NOT EXISTS packet_history ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            dst_ip TEXT,
            src_ip TEXT,
            dst_mac TEXT,
            src_mac TEXT,
            protocol TEXT,
            dst_port INTEGER,
            src_port INTEGER,
            flags TEXT,
            payload TEXT,
            arp_op INTEGER,
            response TEXT
        )
    """
    )

    dst_ip = (
        hash_data(packet.dst_ip) if (packet.dst_ip and anonymize) else packet.dst_ip
    )
    src_ip = (
        hash_data(packet.src_ip) if (packet.src_ip and anonymize) else packet.src_ip
    )
    dst_mac = (
        hash_data(packet.dst_mac) if (packet.dst_mac and anonymize) else packet.dst_mac
    )
    src_mac = (
        hash_data(packet.src_mac) if (packet.src_mac and anonymize) else packet.src_mac
    )
    payload = (
        hash_data(packet.payload) if (packet.payload and anonymize) else packet.payload
    )

    c.execute(
        """
        INSERT INTO packet_history (
            timestamp, dst_ip, src_ip, dst_mac, src_mac, protocol, 
            dst_port, src_port, flags, payload, arp_op, response
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """,
        (
            datetime.now().isoformat(),
            dst_ip,
            src_ip,
            dst_mac,
            src_mac,
            packet.protocol,
            packet.dst_port,
            packet.src_port,
            ",".join(packet.flags) if packet.flags else None,
            payload,
            packet.arp_op,
            response_summary,
        ),
    )

    conn.commit()
    conn.close()
