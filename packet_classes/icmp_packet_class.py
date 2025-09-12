from packet_classes.abstract_packet_class import Packet
from field_validation import (
    validate_ipv4,
    validate_mac,
    validate_payload,
    validate_ipv6,
)


class ICMP_Packet(Packet):
    """
    A class representing an ICMP (Internet Control Message Protocol) packet.

    Inherits from:
        Packet (abstract base class)

    Attributes:
        src_ipv4 (str | None): Optional source IPv4 address for spoofing.
        src_ipv6 (str | None): Optional source IPv6 address for spoofing.
        dst_mac (str | None): Optional destination MAC address (for L2 delivery).
        src_mac (str | None): Optional source MAC address for spoofing.
        payload (str | None): Optional payload string to include in the packet.

    Methods:
        (No public methods beyond inherited functionality)
    """

    __slots__ = ["src_ipv4", "src_ipv6", "dst_mac", "src_mac", "payload"]

    def __init__(
        self,
        dst_ipv4: str,
        dst_ipv6: str,
        src_ipv4: str = None,
        src_ipv6: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        payload: str = None,
        num_pkts: int = 1,
    ):
        super().__init__(
            protocol="icmp", dst_ipv4=dst_ipv4, dst_ipv6=dst_ipv6, num_pkts=num_pkts
        )

        self.src_ipv4 = validate_ipv4(src_ipv4) if src_ipv4 is not None else None
        self.src_ipv6 = validate_ipv6(src_ipv6) if src_ipv6 is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="icmp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="icmp") if src_mac is not None else None
        )
        self.payload = validate_payload(payload) if payload is not None else None
