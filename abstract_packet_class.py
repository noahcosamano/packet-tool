from field_validation import validate_protocol, validate_num_pkts, validate_ip

VALID_PROTOCOLS = {"TCP", "ICMP", "UDP", "ARP"}

class Packet:
    __slots__ = ["protocol", "dst_ip", "num_pkts"]
    
    def __init__(self, protocol: str = None, dst_ip: str = None, num_pkts: int = 1):
        if protocol is None:
            raise ValueError("\tError: Protocol required")
        if dst_ip is None:
            raise ValueError("\tError: Destination IP required")
        
        self.protocol = validate_protocol(protocol)
        self.dst_ip = validate_ip(dst_ip)
        self.num_pkts = validate_num_pkts(num_pkts)
        