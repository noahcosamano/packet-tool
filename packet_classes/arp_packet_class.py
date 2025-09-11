from packet_classes.abstract_packet_class import Packet
from field_validation import validate_ip, validate_mac, validate_arp_op


class ARP_Packet(Packet):
    """
    A class representing an ARP (Address Resolution Protocol) packet.

    Inherits from:
        Packet (abstract base class)

    Attributes:
        src_ip (str): Optional source IP address.
        dst_mac (str): Optional destination MAC address.
        src_mac (str): Optional source MAC address.
        arp_op (int): ARP operation code (1 for request, 2 for reply).

    Methods:
        (None beyond inherited methods; all attributes set on initialization)
    """

    __slots__ = ["src_ip", "dst_mac", "src_mac", "arp_op"]

    def __init__(
        self,
        dst_ip: str,
        src_ip: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        arp_op: int = 1,
        num_pkts: int = 1,
    ):

        super().__init__(protocol="arp", dst_ip=dst_ip, num_pkts=num_pkts)

        self.src_ip = validate_ip(src_ip) if src_ip is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="arp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="arp") if src_mac is not None else None
        )
        self.arp_op = validate_arp_op(arp_op, protocol="arp")
