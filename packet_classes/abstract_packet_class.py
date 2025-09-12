from field_validation import (
    validate_protocol,
    validate_num_pkts,
    validate_ipv4,
    validate_ipv6,
)

VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}


class Packet:
    """
    A base class representing a generic network packet.

    Attributes:
        protocol (str): The protocol type (TCP, UDP, ICMP, or ARP).
        dst_ipv4 (str): The destination IPv4 address.
        dst_ipv6 (str): The destination IPv6 address.
        num_pkts (int): Number of packets to send.

    Methods:
        get_protocol(): Returns the protocol type.
        get_num_pkts(): Returns the number of packets to send.
    """

    __slots__ = ["protocol", "dst_ipv4", "dst_ipv6", "num_pkts"]

    def __init__(
        self,
        protocol: str = None,
        dst_ipv4: str = None,
        dst_ipv6: str = None,
        num_pkts: int = 1,
    ):
        if protocol is None:
            raise ValueError(" Error: Protocol required")
        if dst_ipv4 is None and dst_ipv6 is None:
            raise ValueError(" Error: Destination IPv4 or IPV6 required")

        self.protocol = validate_protocol(protocol)
        self.dst_ipv4 = validate_ipv4(dst_ipv4) if dst_ipv4 else None
        self.dst_ipv6 = validate_ipv6(dst_ipv6) if dst_ipv6 else None
        self.num_pkts = validate_num_pkts(num_pkts)

    def get_protocol(self):
        return self.protocol

    def get_num_pkts(self):
        return self.num_pkts
