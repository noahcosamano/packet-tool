import pytest
from packet_crafter import Packet

def test_packet_creation_arp_valid_opcode_1():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="arp",
        dst_port=None,
        flags=None,
        dst_mac=None,
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload=None,
        num_pkts=2,
    )
    
    assert packet.dst_ip == "192.168.1.1"
    assert packet.protocol == "arp"
    assert packet.dst_port == None
    assert packet.flags == None
    assert packet.dst_mac == "ff:ff:ff:ff:ff:ff"
    assert packet.src_port == None
    assert packet.src_ip == "192.168.1.2"
    assert packet.src_mac == "ff:ee:dd:cc:bb:aa"
    assert packet.payload == None
    assert packet.num_pkts == 2
    assert packet.arp_op == 1
    
def test_packet_creation_arp_valid_opcode_2():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="arp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload=None,
        num_pkts=2,
        arp_op=2
    )
    
    assert packet.dst_ip == "192.168.1.1"
    assert packet.protocol == "arp"
    assert packet.dst_port == None
    assert packet.flags == None
    assert packet.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert packet.src_port == None
    assert packet.src_ip == "192.168.1.2"
    assert packet.src_mac == "ff:ee:dd:cc:bb:aa"
    assert packet.payload == None
    assert packet.num_pkts == 2
    assert packet.arp_op == 2
    
def test_packet_creation_arp_invalid_dst_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.300",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="a.a.a.a",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_port_neg():
    with pytest.raises(ValueError, match="ARP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=-5,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_port_range():
    with pytest.raises(ValueError, match="ARP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=100000,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_port_type():
    with pytest.raises(ValueError, match='ARP does not support ports'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port="a",
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_flags_type():
    with pytest.raises(ValueError, match='ARP does not support flags'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=1,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_flags():
    with pytest.raises(ValueError, match='ARP does not support flags'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags="o",
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_mac_opcode_1():
    with pytest.raises(ValueError, match='ARP op #1 does not support destination MAC'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_dst_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
            arp_op=2
        )
        
def test_packet_creation_arp_invalid_dst_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee:zb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:zb",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
            arp_op=2
        )
        
def test_packet_creation_arp_invalid_dst_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=1,
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
            arp_op=2
        )
        
def test_packet_creation_arp_invalid_src_port_neg():
    with pytest.raises(ValueError, match="ARP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=-5,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_port_range():
    with pytest.raises(ValueError, match="ARP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=100000,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_port_type():
    with pytest.raises(ValueError, match='ARP does not support ports'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port="a",
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=2,
            src_ip="192.168.1",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.300",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="a.a.a.a",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb:az'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:az",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_src_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac=1,
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_arp_invalid_num_pkts_neg():
    with pytest.raises(ValueError, match='Invalid number of packets: -5'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=-5,
        )
        
def test_packet_creation_arp_invalid_num_pkts_range():
    with pytest.raises(ValueError, match='Invalid number of packets: 501'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=501,
        )
        
def test_packet_creation_arp_invalid_num_pkts_type():
    with pytest.raises(ValueError, match='Invalid number of packets: a'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts="a",
        )
    
def test_packet_creation_no_dst_ip():
    with pytest.raises(ValueError, match='Destination IP required'):
        Packet(
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
        
def test_packet_creation_no_protocol():
    with pytest.raises(ValueError, match='Protocol required'):
        Packet(
            dst_ip="192.168.1.1",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=2,
        )
    
def test_packet_arp_no_dst_mac_opcode_1():
    packet = Packet(
            dst_ip="192.168.1.2",
            protocol="arp",
            dst_port=None,
            flags=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=1
        )
    
    assert packet.dst_mac == "ff:ff:ff:ff:ff:ff"
    
def test_packet_arp_no_dst_mac_opcode_2():
    with pytest.raises(ValueError, match="ARP replies require destination MAC"):
        packet = Packet(
                dst_ip="192.168.1.2",
                protocol="arp",
                dst_port=None,
                flags=None,
                src_port=None,
                src_ip="192.168.1.2",
                src_mac="ff:ee:dd:cc:bb:aa",
                payload=None,
                num_pkts=1,
                arp_op=2
            )
    
def test_packet_arp_no_src_port():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="arp",
        dst_port=None,
        flags=None,
        dst_mac=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload=None,
        num_pkts=1
    )
    
    assert packet.src_port == None
    
def test_packet_arp_no_src_ip():
    with pytest.raises(ValueError, match="ARP requires source IP, MAC, and destination IP"):
        Packet(
            dst_ip="192.168.1.2",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_mac="ff:ee:dd:cc:bb:aa",
            payload=None,
            num_pkts=1
        )
    
def test_packet_arp_no_src_mac():
    with pytest.raises(ValueError, match="ARP requires source IP, MAC, and destination IP"):
        packet = Packet(
            dst_ip="192.168.1.2",
            protocol="arp",
            dst_port=None,
            flags=None,
            dst_mac=None,
            src_port=None,
            src_ip="192.168.1.2",
            payload=None,
            num_pkts=1
        )
    
def test_packet_arp_no_payload():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="arp",
        dst_port=None,
        flags=None,
        dst_mac=None,
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        num_pkts=1
    )
    
    assert packet.payload == None

def test_packet_arp_no_num_pkts():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="arp",
        dst_port=None,
        flags=None,
        dst_mac=None,
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload=None
    )
    
    assert packet.num_pkts == 1

