from field_validation import validate_protocol, validate_num_pkts, validate_ipv4

VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}


class Packetv4:
    """
    A base class representing a generic network packet.

    Attributes:
        protocol (str): The protocol type (TCP, UDP, ICMP, or ARP).
        dst_ipv4 (str): The destination IPv4 address.
        num_pkts (int): Number of packets to send.

    Methods:
        get_protocol(): Returns the protocol type.
        get_num_pkts(): Returns the number of packets to send.
    """

    __slots__ = ["protocol", "dst_ipv4", "num_pkts"]

    def __init__(self, protocol: str = None, dst_ipv4: str = None, num_pkts: int = 1):
        if protocol is None:
            raise ValueError(" Error: Protocol required")
        if dst_ipv4 is None:
            raise ValueError(" Error: Destination IPv4 required")

        self.protocol = validate_protocol(protocol)
        self.dst_ipv4 = validate_ipv4(dst_ipv4)
        self.num_pkts = validate_num_pkts(num_pkts)

    def get_protocol(self):
        return self.protocol

    def get_num_pkts(self):
        return self.num_pkts
