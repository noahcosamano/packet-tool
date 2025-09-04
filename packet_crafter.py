"""
DISCLAIMER: This program is intended for educational purposes only. It must NOT be used maliciously
for activities such as probing, flooding, scanning, or any unauthorized network access. Always use
this tool within a controlled environment such as a private lab network or virtual environment.

This program is a basic packet crafter that supports TCP, UDP, and ICMP protocols. It allows sending any number
of packets at once with a specified destination MAC address for Layer 2 traffic, as well as destination IPv4 addresses
for Layer 3 traffic. It also supports crafting packets with payloads, spoofed source IPv4 addresses and source ports.
All packet information and responses sent through this tool will also be logged into a seperate SQL database with hashed IPv4
addresses, MAC addresses, and payloads.

Author: Noah Cosamano
"""

from scapy.all import TCP, sr1, srp1, send, sendp, IP, UDP, Ether, ICMP, Raw, ARP
import ipaddress, re, sqlite3, hashlib, nmap
from datetime import datetime

class Packet:
    __slots__ = ["dst_ip", "dst_mac", "protocol", "dst_port", "flags", "src_port", "src_ip", "src_mac", "payload", 
                 "num_pkts", "arp_op"]
    
    def __init__(self, dst_ip:str, protocol:str, dst_port:int|None = None, flags:str|list|None = None,
                 dst_mac:str|None = None, src_port:int|None = None, src_ip:str|None = None, src_mac:str|None = None,
                 payload:str|None = None, num_pkts:int = 1, arp_op:int|None = 1):
        
        protocol = protocol.lower() # Sets protocol to lower case to verify
        
        if dst_mac:
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', dst_mac): # Ensures MAC address is valid format
                raise ValueError("Invalid destination MAC address")
            self.dst_mac = dst_mac
        else:
            self.dst_mac = dst_mac # Sets to None if user does not input. This is for if you print packet information.
            
        if src_mac:
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', src_mac): # Ensures MAC address is valid format
                raise ValueError("Invalid source MAC address")
            self.src_mac = src_mac
        else:
            self.src_mac = src_mac # Sets to None if user does not input. This is for if you print packet information.
        
        if flags:
            for flag in flags:
                if flag.lower() not in ("f", "s", "r", "p", "a", "u"): # Ensures flag is a valid flag for TCP
                    raise ValueError("Invalid TCP flag(s)")
            self.flags = flags
        else:
            self.flags = None # Sets to None if user does not input. This is for if you print packet information.
        
        if dst_ip:
            try:
                ipaddress.IPv4Address(dst_ip) # Validates IPv4 address format
                self.dst_ip = dst_ip
            except Exception:
                raise ValueError("Invalid destination IP address")
        else:
            self.dst_ip = dst_ip # Sets to None if user does not input. This is for if you print packet information.
        
        if src_ip:
            try: 
                ipaddress.IPv4Address(src_ip) # Validates IPv4 address format
                self.src_ip = src_ip
            except Exception:
                raise ValueError("Invalid source IP address")
        else:
            self.src_ip = src_ip # Sets to None if user does not input. This is for if you print packet information.
            
        if src_port:
            if not isinstance(src_port, int) or not (1 <= src_port <= 65535):
                raise ValueError("Invalid port")
        self.src_port = src_port # Sets to None if user does not input. This is for if you print packet information.
            
        if payload:
            if isinstance(payload, str):
                self.payload = payload
            else:
                raise ValueError("Invalid payload")
        else:
            self.payload = payload # Sets to None if user does not input. This is for if you print packet information.
            
        if isinstance(num_pkts, int):
            self.num_pkts = num_pkts
        else:
            raise ValueError("Invalid number of packets")
        
        if arp_op == 1:
            self.arp_op = arp_op
            self.dst_mac = "ff:ff:ff:ff:ff:ff"
        elif arp_op == 2:
            self.arp_op = arp_op
            if self.dst_mac is None:
                raise ValueError("ARP replies require destination MAC")
        else:
            raise ValueError("Invalid ARP operator")

        if protocol in ("tcp", "udp"):
            self.protocol = protocol
            if dst_port is None:
                raise ValueError("TCP and UDP require a destination port")
            elif isinstance(dst_port, int) and 1 <= dst_port <= 65_535: # TCP and UDP only have 65,535 ports, anything more than this is an error.
                self.dst_port = dst_port
            else:
                raise ValueError("Invalid port")
            
        elif protocol == "icmp":
            self.protocol = protocol
            if flags:
                raise ValueError("ICMP does not support flags")
            if dst_port is not None or src_port is not None:
                raise ValueError("ICMP does not support ports")
            self.dst_port = dst_port; self.src_port = src_port # Sets to None if user does not input. This is for if you print packet information.
            
        elif protocol == "arp":
            self.protocol = protocol
            if flags:
                raise ValueError("ARP does not support flags")
            if dst_port is not None or src_port is not None:
                raise ValueError("ARP does not support ports")
            if payload is not None:
                raise ValueError("ARP does not support payloads")
            self.dst_port = dst_port; self.src_port = src_port # Sets to None if user does not input. This is for if you print packet information.
            if src_ip is None or src_mac is None or dst_ip is None:
                raise ValueError("ARP requires source IP, MAC, and destination IP")
            
        else:
            raise ValueError("Invalid protocol")
            
    def create_packet(self):
        if self.protocol != "arp":
            ip = IP(dst = self.dst_ip) # Sets destination IPv4 for IP layer
            if self.src_ip:
                ip.src = self.src_ip
                
        ether = Ether() # Creates ethernet layer for link layer
        
        if self.payload:
            payload = Raw(load = self.payload.encode())
        else:
            payload = None
        
        if self.protocol == "tcp":
            tcp = TCP(dport = self.dst_port)
            if self.src_port:
                tcp.sport = self.src_port
            if self.flags:
                tcp.flags = ''.join(flag.upper() for flag in self.flags) # Flags are converted to string if user input them as a list
            layer4 = tcp
        
        elif self.protocol == "udp":
            if self.flags:
                raise ValueError("UDP does not support flags")
            udp = UDP(dport = self.dst_port)
            if self.src_port:
                udp.sport = self.src_port
            layer4 = udp
        
        elif self.protocol == "icmp":
            layer4 = ICMP()
            
        elif self.protocol == "arp":
            layer4 = ARP(op = self.arp_op, hwsrc = self.src_mac, psrc = self.src_ip, pdst = self.dst_ip)
            if self.dst_mac is not None:
                ether.dst = self.dst_mac
                layer4.hwdst = self.dst_mac
            
        else: # Currently this program supports TCP, UDP, and ICMP
            raise ValueError("Unsupported protocol")
        
        if self.protocol == "arp":
            pkt = ether / layer4
        else:
            pkt = ip / layer4
            if self.dst_mac or self.src_mac:
                pkt = ether / pkt
        
        if self.dst_mac or self.src_mac:
            if self.dst_mac: ether.dst = self.dst_mac
            if self.src_mac: ether.src = self.src_mac
            pkt = ether / pkt
            
        if payload:
            pkt = pkt / payload
            
        return pkt
    
    def s_packet(self): # Sends one packet
        pkt = self.create_packet()
        index = 1
        
        while index <= self.num_pkts:
            if self.dst_mac or self.src_mac: # Send is a layer 3 function while sendp is a layer 2 function, so if MAC is provided, it uses sendp
                sendp(pkt, verbose = 0)
            else:
                send(pkt, verbose = 0)
                
            log_packet(self, None, True)
            index += 1
            
    def sr_packet(self): # Sends and receives one packet (same as above, except for srp1 and sr1)
        pkt = self.create_packet()
        index = 1
        
        while index <= self.num_pkts:
            if self.dst_mac or self.src_mac:
                response = srp1(pkt, timeout = 3, verbose=0)
            else:
                response = sr1(pkt, timeout = 3, verbose = 0)
                
            if response: # If packet received a response, this will print it
                print(f"Received: {response.summary()}")
            else:
                print("No response")
            
            log_packet(self, response_summary = response.summary() if response else "No response", anonymize = True)
            index += 1
            
        return response
    
    def __str__(self): # Returns packet information to be printed
        return(f"Destination IPv4: {self.dst_ip}\nProtocol: {self.protocol.upper()}\nDestination port: {self.dst_port}\n"
              + f"Flags: {self.flags}\nDestination MAC address: {self.dst_mac}\nSource port: {self.src_port}\n"
              + f"Source IPv4: {self.src_ip}, Source MAC: {self.src_mac}, Payload: {self.payload}")
        
def hash_data(data:str) -> str: # Takes MAC and IPv4 addresses and hashes using SHA256 if anonymize mode is set to True
    return hashlib.sha256(data.encode()).hexdigest()
    
def log_packet(packet:Packet, response_summary:str|None = None, anonymize=True): # Creates a log of packets and responses if given one
    conn = sqlite3.connect("packet_history.sqlite") # seperate SQL db file
    c = conn.cursor()
    
    c.execute(""" 
        CREATE TABLE IF NOT EXISTS packet_history ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            dst_ip TEXT,
            src_ip TEXT,
            dst_mac TEXT,
            src_mac TEXT,
            protocol TEXT,
            dst_port INTEGER,
            src_port INTEGER,
            flags TEXT,
            payload TEXT,
            arp_op INTEGER,
            response TEXT
        )
    """)
    # ^ Creates a new table if one is not made already in file. Contains all information of packet.
    
    dst_ip = hash_data(packet.dst_ip) if (packet.dst_ip and anonymize) else packet.dst_ip  # Hashes sensitive daya
    src_ip = hash_data(packet.src_ip) if (packet.src_ip and anonymize) else packet.src_ip
    dst_mac = hash_data(packet.dst_mac) if (packet.dst_mac and anonymize) else packet.dst_mac
    src_mac = hash_data(packet.src_mac) if (packet.src_mac and anonymize) else packet.src_mac
    payload = hash_data(packet.payload) if (packet.payload and anonymize) else packet.payload
    
    c.execute("""
        INSERT INTO packet_history (
            timestamp, dst_ip, src_ip, dst_mac, src_mac, protocol, 
            dst_port, src_port, flags, payload, arp_op, response
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (
        datetime.now().isoformat(), # Logs date and time of packet
        dst_ip,
        src_ip,
        dst_mac,
        src_mac,
        packet.protocol,
        packet.dst_port,
        packet.src_port,
        ','.join(packet.flags) if packet.flags else None,
        payload,
        packet.arp_op,
        response_summary
    ))
    
    conn.commit() # Pushes changes to SQL file
    conn.close()
    
def main():
    
    pkt1 = Packet("129.21.72.179","ARP",None,None,"ff:fe:08:87:90:73",None,"129.21.108.139","60:45:2e:c8:6f:09")
    pkt1.sr_packet()
    
if __name__ == "__main__":
    main()