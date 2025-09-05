import pytest
from packet_crafter import Packet

def test_packet_creation_tcp_valid():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=2,
    )
    
    assert packet.dst_ip == "192.168.1.1"
    assert packet.protocol == "tcp"
    assert packet.dst_port == 1
    assert packet.flags == ["s"]
    assert packet.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert packet.src_port == 2
    assert packet.src_ip == "192.168.1.2"
    assert packet.src_mac == "ff:ee:dd:cc:bb:aa"
    assert packet.payload == "test"
    assert packet.num_pkts == 2
    
def test_packet_creation_tcp_invalid_dst_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.300",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="a.a.a.a",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_port_neg():
    with pytest.raises(ValueError, match="Invalid port: -5"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=-5,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_port_range():
    with pytest.raises(ValueError, match="Invalid port: 100000"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=100000,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_port_zero():
    with pytest.raises(ValueError, match="Destination port required for TCP and UDP"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=0,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_port_type():
    with pytest.raises(ValueError, match='Invalid port: a'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port="a",
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_flags_type():
    with pytest.raises(ValueError, match='Invalid TCP flags: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags=1,
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_flags():
    with pytest.raises(ValueError, match='Invalid TCP flag: o'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="o",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: aa:bb:cc:dd:ee:zb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:zb",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_dst_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac=1,
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_port_neg():
    with pytest.raises(ValueError, match="Invalid port: -5"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=-5,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_port_range():
    with pytest.raises(ValueError, match="Invalid port: 100000"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=100000,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_port_type():
    with pytest.raises(ValueError, match='Invalid port: a'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port="a",
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_ip_length():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_ip_range():
    with pytest.raises(ValueError, match="Invalid IP address: 192.168.1.300"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.300",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_ip_type():
    with pytest.raises(ValueError, match="Invalid IP address: a.a.a.a"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="a.a.a.a",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_mac_length():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_mac_range():
    with pytest.raises(ValueError, match='Invalid MAC address: ff:ee:dd:cc:bb:az'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:az",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_src_mac_type():
    with pytest.raises(ValueError, match='Invalid MAC address: 1'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac=1,
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_tcp_invalid_num_pkts_neg():
    with pytest.raises(ValueError, match='Invalid number of packets: -5'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=-5,
        )
        
def test_packet_creation_tcp_invalid_num_pkts_range():
    with pytest.raises(ValueError, match='Invalid number of packets: 501'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=501,
        )
        
def test_packet_creation_tcp_invalid_num_pkts_type():
    with pytest.raises(ValueError, match='Invalid number of packets: a'):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts="a",
        )
    
def test_packet_creation_tcp_valid_multiple_flags():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="tcp",
        dst_port=1,
        flags="sap",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=2,
    )
    
    assert packet.flags == ["s","a","p"]
    
def test_packet_creation_no_dst_ip():
    with pytest.raises(ValueError, match='Destination IP required'):
        Packet(
            protocol="tcp",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
        
def test_packet_creation_no_protocol():
    with pytest.raises(ValueError, match='Protocol required'):
        Packet(
            dst_ip="192.168.1.1",
            dst_port=1,
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=2,
        )
    
def test_packet_tcp_no_dst_port():
    with pytest.raises(ValueError, match="Destination port required for TCP and UDP"):
        Packet(
            dst_ip="192.168.1.1",
            protocol="tcp",
            flags="s",
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_port = 2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=1
        )
    
def test_packet_tcp_no_flags():
    packet = Packet(
        dst_ip="192.168.1.1",
        protocol="tcp",
        dst_port=1,
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port = 2,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=1
    )
    
    assert packet.flags == None
    
def test_packet_tcp_no_dst_mac():
    packet = Packet(
            dst_ip="192.168.1.2",
            protocol="tcp",
            dst_port=1,
            flags="s",
            src_port=2,
            src_ip="192.168.1.2",
            src_mac="ff:ee:dd:cc:bb:aa",
            payload="test",
            num_pkts=1
        )
    
    assert packet.dst_mac == None
    
def test_packet_tcp_no_src_port():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=1
    )
    
    assert packet.src_port == None
    
def test_packet_tcp_no_src_ip():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
        num_pkts=1
    )
    
    assert packet.src_ip == None
    
def test_packet_tcp_no_src_mac():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_ip="192.168.1.2",
        payload="test",
        num_pkts=1
    )
    
    assert packet.src_mac == None
    
def test_packet_tcp_no_payload():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        num_pkts=1
    )
    
    assert packet.payload == None

def test_packet_tcp_no_num_pkts():
    packet = Packet(
        dst_ip="192.168.1.2",
        protocol="tcp",
        dst_port=1,
        flags="s",
        dst_mac="aa:bb:cc:dd:ee:ff",
        src_port=2,
        src_ip="192.168.1.2",
        src_mac="ff:ee:dd:cc:bb:aa",
        payload="test",
    )
    
    assert packet.num_pkts == 1

