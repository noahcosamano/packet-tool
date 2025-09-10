from abstract_packet_class import Packet
from field_validation import validate_port, validate_ip, validate_mac, validate_tcp_flags, validate_payload

class TCP_Packet(Packet):
    __slots__ = ["dst_port", "src_port", "src_ip", "dst_mac", "src_mac", "flags", "payload"]
    
    def __init__(self, dst_ip: str,  dst_port: int = None, src_port: int = None,
                 src_ip: str = None, dst_mac: str = None, src_mac: str = None, 
                 flags: list[str] | str = None, payload: str = None, num_pkts: int = 1):
        
        super().__init__(protocol="tcp", dst_ip=dst_ip, num_pkts=num_pkts)
        
        if dst_port is None:
            raise ValueError("\tError: Destination port is required for TCP protocol")
        
        self.dst_port = validate_port(dst_port, "tcp")
        self.src_port = validate_port(src_port, "tcp") if src_port is not None else None
        
        self.src_ip = validate_ip(src_ip) if src_ip is not None else None
        self.dst_mac = validate_mac(dst_mac, protocol="tcp") if dst_mac is not None else None
        self.src_mac = validate_mac(src_mac, protocol="tcp") if src_mac is not None else None
        self.flags = validate_tcp_flags(flags,protocol = "tcp") if flags is not None else None
        self.payload = validate_payload(payload) if payload is not None else None
        
        
        