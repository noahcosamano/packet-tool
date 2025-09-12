from field_validation import validate_protocol, validate_num_pkts, validate_ipv6

VALID_PROTOCOLS = {"TCP", "ICMPv6", "UDP"}


class Packetv6:
    """
    A base class representing a generic network packet.

    Attributes:
        protocol (str): The protocol type (TCP, UDP, or ICMPv6).
        dst_ipv6 (str): The destination IPv6 address.
        num_pkts (int): Number of packets to send.

    Methods:
        get_protocol(): Returns the protocol type.
        get_num_pkts(): Returns the number of packets to send.
    """

    __slots__ = ["protocol", "dst_ipv4", "num_pkts"]

    def __init__(self, protocol: str = None, dst_ipv6: str = None, num_pkts: int = 1):
        if protocol is None:
            raise ValueError(" Error: Protocol required")
        if dst_ipv6 is None:
            raise ValueError(" Error: Destination IPv6 required")

        self.protocol = validate_protocol(protocol)
        self.dst_ipv6 = validate_ipv6(dst_ipv6)
        self.num_pkts = validate_num_pkts(num_pkts)

    def get_protocol(self):
        return self.protocol

    def get_num_pkts(self):
        return self.num_pkts
