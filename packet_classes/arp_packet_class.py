from packet_classes.abstract_packetv4_class import Packetv4
from field_validation import validate_ip, validate_mac, validate_arp_op


class ARP_Packet(Packetv4):
    """
    A class representing an ARP (Address Resolution Protocol) packet.

    Inherits from:
        Packet (abstract base class)

    Attributes:
        src_ipv4 (str): Optional source IPv4 address.
        dst_mac (str): Optional destination MAC address.
        src_mac (str): Optional source MAC address.
        arp_op (int): ARP operation code (1 for request, 2 for reply).

    Methods:
        (None beyond inherited methods; all attributes set on initialization)
    """

    __slots__ = ["src_ipv4", "dst_mac", "src_mac", "arp_op"]

    def __init__(
        self,
        dst_ipv4: str,
        src_ipv4: str = None,
        dst_mac: str = None,
        src_mac: str = None,
        arp_op: int = 1,
        num_pkts: int = 1,
    ):

        super().__init__(protocol="arp", dst_ipv4=dst_ipv4, num_pkts=num_pkts)

        self.src_ipv4 = validate_ip(src_ipv4) if src_ipv4 is not None else None
        self.dst_mac = (
            validate_mac(dst_mac, protocol="arp") if dst_mac is not None else None
        )
        self.src_mac = (
            validate_mac(src_mac, protocol="arp") if src_mac is not None else None
        )
        self.arp_op = validate_arp_op(arp_op, protocol="arp")
