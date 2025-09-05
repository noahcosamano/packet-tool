import pytest
from packet_crafter import Packet

def test_packet_creation_icmp_valid():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="icmp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=2,
    )
    
    assert packet.dst_ip == "192.168.1.1"
    assert packet.protocol == "icmp"
    assert packet.dst_port == None
    assert packet.flags == None
    assert packet.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert packet.src_port == None
    assert packet.src_ip == "192.168.1.2"
    assert packet.src_mac == "ff:ee:dd:cc:bb:aa"
    assert packet.payload == "test"
    assert packet.num_pkts == 2
    
def test_packet_creation_icmp_invalid_dst_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.300",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="a.a.a.a",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_port_neg():
    with pytest.raises(ValueError, match="ICMP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=-5,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_port_range():
    with pytest.raises(ValueError, match="ICMP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=100000,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_port_type():
    with pytest.raises(ValueError, match='ICMP does not support ports'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port="a",
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_flags_type():
    with pytest.raises(ValueError, match='ICMP does not support flags'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=1,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_flags():
    with pytest.raises(ValueError, match='ICMP does not support flags'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags="o",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee:zb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:zb",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_dst_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac=1,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_port_neg():
    with pytest.raises(ValueError, match="ICMP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=-5,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_port_range():
    with pytest.raises(ValueError, match="ICMP does not support ports"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=100000,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_port_type():
    with pytest.raises(ValueError, match='ICMP does not support ports'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port="a",
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.300",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="a.a.a.a",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb:az'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:az",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_src_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac=1,
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_icmp_invalid_num_pkts_neg():
    with pytest.raises(ValueError, match='Invalid number of packets: -5'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=-5,
        )
        
def test_packet_creation_icmp_invalid_num_pkts_range():
    with pytest.raises(ValueError, match='Invalid number of packets: 501'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=501,
        )
        
def test_packet_creation_icmp_invalid_num_pkts_type():
    with pytest.raises(ValueError, match='Invalid number of packets: a'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts="a",
        )
    
def test_packet_creation_no_dst_ip():
    with pytest.raises(ValueError, match='Destination IP required'):
        Packet(
            protocol="icmp",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_no_protocol():
    with pytest.raises(ValueError, match='Protocol required'):
        Packet(
            dst_ip="192.168.1.1",
            dst_port=None,
            flags=None,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
    
def test_packet_icmp_no_dst_mac():
    packet = Packet(
            dst_ip="192.168.1.2",
            protocol="icmp",
            dst_port=None,
            flags=None,
            src_port=None,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=1
        )
    
    assert packet.dst_mac == None
    
def test_packet_icmp_no_src_ip():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="icmp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=1
    )
    
    assert packet.src_ip == None
    
def test_packet_icmp_no_src_mac():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="icmp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_ip="192.168.1.2",
        payload="test",
        num_pkts=1
    )
    
    assert packet.src_mac == None
    
def test_packet_icmp_no_payload():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="icmp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        num_pkts=1
    )
    
    assert packet.payload == None

def test_packet_icmp_no_num_pkts():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="icmp",
        dst_port=None,
        flags=None,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=None,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
    )
    
    assert packet.num_pkts == 1

