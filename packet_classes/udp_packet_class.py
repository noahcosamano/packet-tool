from packet_classes.abstract_packet_class import Packet
from field_validation import (
    validate_port,
    validate_ipv4,
    validate_ipv6,
    validate_mac,
    validate_payload,
)


class UDP_Packet(Packet):
    """
    Represents a UDP packet with optional configuration for source/destination IPv4s, ports,
    MAC addresses, and a payload. Inherits from the abstract Packet base class.

    Attributes:
        dst_port (int): Destination UDP port (required).
        src_port (int, optional): Source UDP port.
        src_ipv4 (str, optional): Source IPv4 address.
        src_ipv6 (str, optional): Source IPv6 address.
        dst_mac (str, optional): Destination MAC address.
        src_mac (str, optional): Source MAC address.
        payload (str, optional): Optional payload for the UDP packet.
    """

    __slots__ = [
        "dst_port",
        "src_port",
        "src_ipv4",
        "src_ipv6",
        "dst_mac",
        "src_mac",
        "payload",
    ]

    def __init__(
        self,
        dst_ipv4: str,
        dst_ipv6: str,
        dst_port: int = None,
        src_port: int = None,
        src_ipv4: str = None,
        src_ipv6: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        payload: str = None,
        num_pkts: int = 1,
    ):
        super().__init__(
            protocol="udp", dst_ipv4=dst_ipv4, dst_ipv6=dst_ipv6, num_pkts=num_pkts
        )

        if dst_port is None:
            raise ValueError(" Error: Destination port is required for UDP protocol")

        self.dst_port = validate_port(dst_port, "udp")
        self.src_port = validate_port(src_port, "udp") if src_port is not None else None

        self.src_ipv4 = validate_ipv4(src_ipv4) if src_ipv4 is not None else None
        self.src_ipv6 = validate_ipv6(src_ipv6) if src_ipv6 is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="udp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="udp") if src_mac is not None else None
        )
        self.payload = validate_payload(payload) if payload is not None else None
