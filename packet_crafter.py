"""
DISCLAIMER: This program is intended for educational purposes only. It must NOT be used maliciously
for activities such as probing, flooding, scanning, or any unauthorized network access. Always use
this tool within a controlled environment such as a private lab network or virtual environment.

This program is a basic packet crafter that supports TCP, UDP, and ICMP protocols. It allows sending packets
with a specified destination MAC address for Layer 2 traffic, as well as destination IPv4 addresses
for Layer 3 traffic. It also supports crafting packets with spoofed source IPv4 addresses and source ports.

Author: Noah Cosamano
"""

from scapy.all import TCP,sr1,sr,srp1,srp,send,sendp,IP,UDP,Ether,ICMP
import ipaddress, re, sqlite3

class Packet:
    __slots__ = ["dst_ip","dst_mac","protocol","dst_port","flags","src_port","src_ip"]
    
    def __init__(self,dst_ip:str,protocol:str,dst_port:int|None=None,flags:str|list|None=None,
                 dst_mac:str|None=None,src_port:int|None=None,src_ip:str|None=None):
        
        protocol = protocol.lower() # Sets protocol to lower case to verify
        
        if dst_mac:
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',dst_mac): # Ensures MAC address is valid format
                raise ValueError("Invalid MAC address")
            self.dst_mac = dst_mac
        else:
            self.dst_mac = dst_mac # Sets to None if user does not input. This is for if you print packet information.
        
        if flags:
            for flag in flags:
                if flag.lower() not in ("f","s","r","p","a","u"): # Ensures flag is a valid flag for TCP
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

        if protocol in ("tcp","udp"):
            self.protocol = protocol
            if dst_port is None:
                raise ValueError("TCP and UDP require a destination port")
            elif isinstance(dst_port,int) and 1 <= dst_port <= 65_535: # TCP and UDP only have 65,535 ports, anything more than this is an error.
                self.dst_port = dst_port
            else:
                raise ValueError("Invalid port")
            
        elif protocol == "icmp":
            self.protocol = protocol
            if flags:
                raise ValueError("ICMP does not support flags")
            if dst_port is not None or src_port is not None:
                raise ValueError("ICMP does not support ports")
            self.dst_port = dst_port # Sets to None if user does not input. This is for if you print packet information.
            self.src_port = src_port # Sets to None if user does not input. This is for if you print packet information.
            
        else:
            raise ValueError("Invalid protocol")
        
        if src_port:
            if not isinstance(src_port,int) or not (1 <= src_port <= 65535):
                raise ValueError("Invalid port")
        self.src_port = src_port # Sets to None if user does not input. This is for if you print packet information.
            
    def create_packet(self):
        ip = IP(dst=self.dst_ip) # Sets destination IPv4 for IP layer
        
        if self.src_ip:
            ip.src = self.src_ip
        
        if self.protocol == "tcp":
            tcp = TCP(dport=self.dst_port)
            if self.src_port:
                tcp.sport = self.src_port
            if self.flags:
                tcp.flags = ''.join(flag.upper() for flag in self.flags) # Flags are converted to string if user input them as a list
            layer4 = tcp
        
        elif self.protocol == "udp":
            if self.flags:
                raise ValueError("UDP does not support flags")
            udp = UDP(dport=self.dst_port)
            if self.src_port:
                udp.sport = self.src_port
            layer4 = udp
        
        elif self.protocol == "icmp":
            layer4 = ICMP()
            
        else: # Currently this program supports TCP, UDP, and ICMP
            raise ValueError("Unsupported protocol")
        
        pkt = ip / layer4
        
        if self.dst_mac: # If packet contains destination MAC address by user, the packet is automatically created at layer 2
            pkt = Ether(dst=self.dst_mac) / pkt
            
        return pkt
    
    def s_packet(self): # Sends one packet
        pkt = self.create_packet()
        
        if self.dst_mac is None: # Send is a layer 3 function while sendp is a layer 2 function, so if MAC is provided, it uses sendp
            send(pkt,verbose=1)
        else:
            sendp(pkt,verbose=1)
            
    def sr_packet(self): # Sends and receives one packet (same as above, except for srp1 and sr1)
        pkt = self.create_packet()
        
        if self.dst_mac:
            response = srp1(pkt,timeout=1,verbose=1)
        else:
            response = sr1(pkt,timeout=1,verbose=1)
            
        if response: # If packet received a response, this will print it
            print(f"Received: {response.summary()}")
        else:
            print("No response")
            
        return response
    
    def __str__(self): # Returns packet information to be printed
        return(f"Destination IPv4: {self.dst_ip}\nProtocol: {self.protocol.upper()}\nDestination port: {self.dst_port}\n"
              + f"Flags: {self.flags}\nDestination MAC address: {self.dst_mac}\nSource port: {self.src_port}\n"
              + f"Source IPv4: {self.src_ip}")
    
def main():
    pkt1 = Packet("192.168.1.1","TCP",12089,"SAP","ff:ff:ff:ff:ff",1,"192.168.1.2")
    print(pkt1)
    pkt1.s_packet()
    
if __name__ == "__main__":
    main()
        
        
            
        
