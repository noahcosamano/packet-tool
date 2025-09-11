from packet_classes.abstract_packet_class import Packet
from field_validation import validate_port, validate_ip, validate_mac, validate_payload


class UDP_Packet(Packet):
    """
    Represents a UDP packet with optional configuration for source/destination IPs, ports,
    MAC addresses, and a payload. Inherits from the abstract Packet base class.

    Attributes:
        dst_port (int): Destination UDP port (required).
        src_port (int, optional): Source UDP port.
        src_ip (str, optional): Source IPv4 address.
        dst_mac (str, optional): Destination MAC address.
        src_mac (str, optional): Source MAC address.
        payload (str, optional): Optional payload for the UDP packet.
    """

    __slots__ = ["dst_port", "src_port", "src_ip", "dst_mac", "src_mac", "payload"]

    def __init__(
        self,
        dst_ip: str,
        dst_port: int = None,
        src_port: int = None,
        src_ip: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        payload: str = None,
        num_pkts: int = 1,
    ):
        super().__init__(protocol="udp", dst_ip=dst_ip, num_pkts=num_pkts)

        if dst_port is None:
            raise ValueError(" Error: Destination port is required for UDP protocol")

        self.dst_port = validate_port(dst_port, "udp")
        self.src_port = validate_port(src_port, "udp") if src_port is not None else None

        self.src_ip = validate_ip(src_ip) if src_ip is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="udp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="udp") if src_mac is not None else None
        )
        self.payload = validate_payload(payload) if payload is not None else None
