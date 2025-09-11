from field_validation import validate_protocol, validate_num_pkts, validate_ip

VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}


class Packet:
    """
    A base class representing a generic network packet.

    Attributes:
        protocol (str): The protocol type (TCP, UDP, ICMP, or ARP).
        dst_ip (str): The destination IP address.
        num_pkts (int): Number of packets to send.

    Methods:
        get_protocol(): Returns the protocol type.
        get_num_pkts(): Returns the number of packets to send.
    """

    __slots__ = ["protocol", "dst_ip", "num_pkts"]

    def __init__(self, protocol: str = None, dst_ip: str = None, num_pkts: int = 1):
        if protocol is None:
            raise ValueError(" Error: Protocol required")
        if dst_ip is None:
            raise ValueError(" Error: Destination IP required")

        self.protocol = validate_protocol(protocol)
        self.dst_ip = validate_ip(dst_ip)
        self.num_pkts = validate_num_pkts(num_pkts)

    def get_protocol(self):
        return self.protocol

    def get_num_pkts(self):
        return self.num_pkts
