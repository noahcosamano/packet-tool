import sqlite3
import hashlib
from datetime import datetime
from scapy.layers.inet import TCP, IP, IPv6, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.sendrecv import send, sendp, sr1, srp1
from packet_classes.icmp_packet_class import ICMP_Packet
from packet_classes.arp_packet_class import ARP_Packet
from packet_classes.tcp_packet_class import TCP_Packet
from packet_classes.udp_packet_class import UDP_Packet


def create_base_packet(field_values: dict):
    """
    Creates the base packet object based on protocol and required fields.

    Args:
        field_values (dict): Dictionary containing user-specified fields.

    Raises:
        ValueError: If required fields are missing or protocol is unsupported.

    Returns:
        Packet object corresponding to the protocol (TCP_Packet, UDP_Packet, ICMP_Packet, or ARP_Packet).
    """
    protocol = field_values.get("protocol")
    if not protocol:
        raise ValueError("Error: Protocol is required")

    dst_ipv4 = field_values.get("dst_ipv4")
    dst_ipv6 = field_values.get("dst_ipv6")

    dst_ip = dst_ipv4 if dst_ipv4 else dst_ipv6
    is_ipv6 = dst_ipv6 is not None

    if not dst_ipv4 and not dst_ipv6:
        raise ValueError("Error: Destination IPv4 or IPv6 address is required")
    if dst_ipv4 and dst_ipv6:
        raise ValueError("Error: Only one of dst_ipv4 or dst_ipv6 should be provided")

    if protocol == "tcp":
        if "dst_port" not in field_values:
            raise ValueError(" Error: Destination port is required for TCP")
        return TCP_Packet(dst_ip, field_values["dst_port"], ipv6=is_ipv6)

    elif protocol == "udp":
        if "dst_port" not in field_values:
            raise ValueError(" Error: Destination port is required for UDP")
        return UDP_Packet(dst_ip, field_values["dst_port"], ipv6=is_ipv6)

    elif protocol == "icmp":
        return ICMP_Packet(dst_ip, ipv6=is_ipv6)

    elif protocol == "arp":
        if dst_ipv6:
            raise ValueError("Error: ARP does not support IPv6 addresses")
        return ARP_Packet(dst_ip)

    else:
        raise ValueError(f"Error: Unsupported protocol '{protocol}'")


def create_packet(field_values: dict):
    """
    Constructs a full packet including Ethernet, IPv4, Layer 4, and payload layers,
    based on the provided field values.

    Args:
        field_values (dict): Dictionary containing packet fields and options.

    Returns:
        Scapy Packet object ready for sending.

    Raises:
        ValueError: On missing fields or unsupported protocols.
    """
    try:
        packet = create_base_packet(field_values)
    except Exception as e:
        print(e)
        return

    ether = (
        Ether() if field_values.get("dst_mac") or field_values.get("src_mac") else None
    )
    payload = (
        Raw(load=field_values.get("payload").encode())
        if field_values.get("payload")
        else None
    )

    if isinstance(packet, ARP_Packet):
        arp = ARP(
            op=int(field_values.get("arp_op")),
            hwsrc=field_values.get("src_mac"),
            hwdst=(
                field_values.get("dst_mac")
                if field_values.get("dst_mac")
                else "00:00:00:00:00:00"
            ),
            psrc=field_values.get("src_ipv4"),
            pdst=field_values.get("dst_ipv4"),
        )
        packet = ether / arp if ether else arp
        return packet

    is_ipv6 = "dst_ipv6" in field_values
    if is_ipv6:
        ip = IPv6(dst=field_values["dst_ipv6"])
        if field_values.get("src_ipv6"):
            ip.src = field_values["src_ipv6"]

    else:
        ip = IP(dst=field_values["dst_ipv4"])
        if field_values.get("src_ipv4"):
            ip.src = field_values["src_ipv4"]

    if isinstance(packet, TCP_Packet):
        layer4 = TCP(dport=int(field_values.get("dst_port")))
        if field_values.get("src_port"):
            layer4.sport = int(field_values.get("src_port"))
        if field_values.get("flags"):
            layer4.flags = "".join(field_values.get("flags")).upper()

    elif isinstance(packet, UDP_Packet):
        layer4 = UDP(dport=int(field_values.get("dst_port")))
        if field_values.get("src_port"):
            layer4.sport = field_values.get("src_port")

    elif isinstance(packet, ICMP_Packet):
        layer4 = ICMP()

    else:
        raise ValueError(" Error: Unsupported packet protocol")

    packet = ip / layer4
    if payload:
        packet = packet / payload
    if ether:
        if packet.dst_mac:
            ether.dst = packet.dst_mac
        if packet.src_mac:
            ether.src = packet.src_mac
        packet = ether / packet

    return packet


def send_packet(packet, field_values: dict):
    """
    Sends the constructed packet multiple times as specified in 'num_pkts'.

    Args:
        packet: Scapy packet object to be sent.
        field_values (dict): Dictionary containing user-specified fields including number of packets.
    """
    num_pkts = int(field_values.get("num_pkts") or 1)
    for _ in range(num_pkts):

        if field_values.get("dst_mac") or field_values.get("src_mac"):
            sendp(packet, verbose=0)
        else:
            send(packet, verbose=0)

        print(f" {field_values.get("protocol").upper()} packet(s) sent successfully")

        log_packet(packet, field_values)


def send_receive_packet(packet, field_values: dict):
    """
    Sends the packet and waits for a response, optionally sending multiple packets.

    Args:
        packet: Scapy packet object to be sent.
        field_values (dict): Dictionary containing user-specified fields including number of packets.

    Returns:
        Response packet if received, None otherwise.
    """
    num_pkts = int(field_values.get("num_pkts") or 1)
    for _ in range(num_pkts):

        if field_values.get("dst_mac") or field_values.get("src_mac"):
            response = srp1(packet, timeout=3, verbose=0)
        else:
            response = sr1(packet, timeout=3, verbose=0)

        print(
            f" {field_values.get("protocol").upper()} packet(s) sent successfully. Waiting for response..."
        )

        log_packet(
            packet,
            field_values,
            response_summary=response.summary() if response else " No response",
        )

        if response:
            print(f" Received: {response.summary()}")
        else:
            print(" No response")

    return response


def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def log_packet(field_values: dict, response_summary: str | None = None, anonymize=True):
    """
    Logs packet details and optionally anonymizes sensitive data before storing in SQLite DB.

    Args:
        packet: The sent packet object.
        field_values (dict): Dictionary of packet field values.
        response_summary (str | None): Summary of response packet or None.
        anonymize (bool): Whether to hash sensitive information for privacy.
    """
    conn = sqlite3.connect("packet_history.sqlite")
    c = conn.cursor()

    c.execute(
        """ 
        CREATE TABLE IF NOT EXISTS packet_history ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            dst_ipv4 TEXT,
            src_ipv4 TEXT,
            dst_ipv6 TEXT,
            src_ipv6 TEXT,
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

    dst_ipv4 = (
        hash_data(field_values.get("dst_ipv4"))
        if (field_values.get("dst_ipv4") and anonymize)
        else field_values.get("dst_ipv4")
    )
    src_ipv4 = (
        hash_data(field_values.get("src_ipv4"))
        if (field_values.get("src_ipv4") and anonymize)
        else field_values.get("src_ipv4")
    )
    dst_ipv6 = (
        hash_data(field_values.get("dst_ipv6"))
        if (field_values.get("dst_ipv6") and anonymize)
        else field_values.get("dst_ipv6")
    )
    src_ipv6 = (
        hash_data(field_values.get("src_ipv6"))
        if (field_values.get("src_ipv6") and anonymize)
        else field_values.get("src_ipv6")
    )
    dst_mac = (
        hash_data(field_values.get("dst_mac"))
        if (field_values.get("dst_mac") and anonymize)
        else field_values.get("dst_mac")
    )
    src_mac = (
        hash_data(field_values.get("src_mac"))
        if (field_values.get("src_mac") and anonymize)
        else field_values.get("src_mac")
    )
    payload = (
        hash_data(field_values.get("payload"))
        if (field_values.get("payload") and anonymize)
        else field_values.get("payload")
    )

    c.execute(
        """
        INSERT INTO packet_history (
            timestamp, dst_ipv4, src_ipv4, dst_ipv6, src_ipv6, dst_mac, src_mac, protocol, 
            dst_port, src_port, flags, payload, arp_op, response
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """,
        (
            datetime.now().isoformat(),
            dst_ipv4,
            src_ipv4,
            dst_ipv6,
            src_ipv6,
            dst_mac,
            src_mac,
            field_values.get("protocol"),
            field_values.get("dst_port"),
            field_values.get("src_port"),
            ",".join(field_values.get("flags")) if field_values.get("flags") else None,
            payload,
            field_values.get("arp_op"),
            response_summary,
        ),
    )

    conn.commit()
    conn.close()
