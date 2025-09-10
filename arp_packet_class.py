from abstract_packet_class import Packet
from field_validation import validate_ip, validate_mac, validate_arp_op

class ARP_Packet(Packet):
    __slots__ = ["src_ip","dst_mac","src_mac","arp_op"]
    
    def __init__(self, dst_ip: str, src_ip: str = None, dst_mac: str = None,
                 src_mac: str = None, arp_op: int = 1, num_pkts: int = 1):
        
        super().__init__(protocol="arp",dst_ip=dst_ip,num_pkts=num_pkts)
        
        self.src_ip = validate_ip(src_ip) if src_ip is not None else None
        self.dst_mac = validate_mac(dst_mac, protocol="tcp") if dst_mac is not None else None
        self.src_mac = validate_mac(src_mac, protocol="tcp") if src_mac is not None else None
        self.arp_op = validate_arp_op(arp_op, protocol="arp")