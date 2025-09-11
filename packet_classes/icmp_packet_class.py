from packet_classes.abstract_packet_class import Packet
from field_validation import validate_ip, validate_mac, validate_payload


class ICMP_Packet(Packet):
    """
    A class representing an ICMP (Internet Control Message Protocol) packet.

    Inherits from:
        Packet (abstract base class)

    Attributes:
        src_ip (str | None): Optional source IP address for spoofing.
        dst_mac (str | None): Optional destination MAC address (for L2 delivery).
        src_mac (str | None): Optional source MAC address for spoofing.
        payload (str | None): Optional payload string to include in the packet.

    Methods:
        (No public methods beyond inherited functionality)
    """

    __slots__ = ["src_ip", "dst_mac", "src_mac", "payload"]

    def __init__(
        self,
        dst_ip: str,
        src_ip: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        payload: str = None,
        num_pkts: int = 1,
    ):
        super().__init__(protocol="icmp", dst_ip=dst_ip, num_pkts=num_pkts)

        self.src_ip = validate_ip(src_ip) if src_ip is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="icmp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="icmp") if src_mac is not None else None
        )
        self.payload = validate_payload(payload) if payload is not None else None
