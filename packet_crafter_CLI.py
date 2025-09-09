"""
DISCLAIMER: This program is intended for educational purposes only. It must NOT be used maliciously
for activities such as probing, flooding, scanning, or any unauthorized network access. Always use
this tool within a controlled environment such as a private lab network or virtual environment.

This program is a basic packet crafter that supports TCP, UDP, ICMP, and ARP protocols. When ran, it opens
a prompt that allows users to create and send packets at the command line using specific commands. This 
program allows sending a capped number of packets at once with a specified destination MAC address for Layer 
2 traffic, as well as destination IPv4 addresses for Layer 3 traffic. It also supports crafting packets with 
payloads, spoofed source IPv4 addresses, source ports, and MAC addresses. All packet information and responses
sent through this tool will also be logged into a seperate SQL database with hashed IPv4 addresses, MAC 
addresses, and payloads.

Author: Noah Cosamano
"""

from packet_crafter_logic import *
import time, sys

translation = {"-p" : "protocol",
               "-dip" : "dst_ip",
               "-sip" : "src_ip",
               "-dp" : "dst_port",
               "-sp" : "src_port",
               "-dm" : "dst_mac",
               "-sm" : "src_mac",
               "-f" : "flags",
               "-np" : "num_pkts",
               "-pl" : "payload",
               "-op" : "arp_op"}

ALL_COMMANDS = {"? / help": "Displays all commands",
                "exit" : "Exits the program",
                "--s": "Sends packet after packet has been created",
                "--sr": "Sends packet and waits for reply after packet has been created",
                "(command) ?" : "Lists all options for command, (eg. -p ?)",
                "-p": "Protocol",
                "-dip": "Destination IPv4",
                "-sip": "Source IPv4",
                "-dp" : "Destination port",
                "-sp" : "Source port",
                "-dm" : "Destination MAC",
                "-sm" : "Source MAC",
                "-f" : "Flags",
                "-np" : "Number of packets",
                "-pl" : "Payload",
                "-op" : "ARP operator"}
      
def get_user_input():
    while True:
        user_input = input(">> ").strip().lower() 
        
        if user_input in ("help","?"):
            for command, meaning in ALL_COMMANDS.items():
                print(f"  {command} -> {meaning}") 
                
        elif user_input == "exit":
            sys.exit()
                
        else:
            return user_input
        
def flag_help(flag):
    match flag:
        case "-p":
            for protocol in VALID_PROTOCOLS:
                print(f"  {protocol}")
        case "-dip" | "-sip":
            print("\tx.x.x.x, x = 1-255, (eg. 192.168.52.3)")
        case "-dp" | "-sp":
            print("\t1-65535")
        case "-dm" | "-sm":
            print("\tx:x:x:x:x:x, x = 1-9 a-F, (eg. a5:6e:f0:b3:e8:98)")
        case "-f":
            for flag in VALID_TCP_FLAGS:
                print(f"  {flag}")
        case "-np":
            print("\t1-500")
        case "-pl":
            print("\tany text")
        case "-op":
            print("\t1 or 2")
            
        
def parse_cli():
    while True:
        user_input = get_user_input()
        if not user_input:
            continue   
        
        input_translated = {}
        tokens = []
        quotes = False
        buffer = ""
        
        for part in user_input.strip().split():
            if part.startswith('"') and not part.endswith('"'):
                quotes = True
                buffer = part[1:]
            elif quotes:
                if part.endswith('"'):
                    buffer += " " + part[:-1]
                    tokens.append(buffer)
                    buffer = ""
                    quotes = False
                else:
                    buffer += " " + part
            else:
                tokens.append(part)
                
        if quotes:
            print("\tError: Unclosed quotes in input")
            continue
        
        index = 0
        while index < len(tokens):
            command = tokens[index]
            
            if command in translation:
                try:
                    value = tokens[index + 1]
                    if value.startswith("-") and value in translation:
                        print(f"\tError: Missing value for {command}")
                        break
                    
                    elif value == "?":
                        flag_help(command)
                        break
                    
                    input_translated[translation[command]] = value
                    index += 2
                except IndexError:
                    print(f"\tError: Missing value for {command}")
                    break
                        
            else:
                print(f"\tError: Unknown command: {command}")
                break
        else:
            return input_translated
        
def verify_field(translated_data: dict):
    try:
        protocol = None
        for item, key in translated_data.items():
            match item.lower():
                case "protocol":
                    protocol = validate_protocol(key)
                case "dst_ip" | "src_ip":
                    validate_ip(key)
                case "dst_mac" | "src_mac":
                    if protocol == None:
                        raise ValueError("\tError: Protocol required")
                    validate_mac(key, protocol)
                case "flags":
                    if protocol == None:
                        raise ValueError("\tError: Protocol required")
                    validate_tcp_flags(key, protocol)
                case "dst_port" | "src_port":
                    if protocol == None:
                        raise ValueError("\tError: Protocol required")
                    validate_port(key, protocol)
                case "num_pkts":
                    validate_num_pkts(key)
                case "arp_op":
                    validate_arp_op(key, protocol)
                case "payload":
                    validate_payload(key)
        
        return True
    except Exception as e:
        print(e)
        return False

def translate_to_pkt(translated_data):
    if not verify_field(translated_data):
        return False
    
    int_fields = ["dst_port","src_port","num_pkts","arp_op"]
    for field in int_fields:
        if field in translated_data:
            try:
                translated_data[field] = int(translated_data[field])
            except ValueError:
                print(f"\tError: Invalid integer for {field}")
                return
    
    try:
        pkt = Packet(**translated_data)
        print(f"\t{pkt.protocol.upper()} packet(s) created")
        command_pkt(pkt)
    except Exception as e:
        print(e)
        
def command_pkt(packet : Packet):
    attempts = 0
    
    while attempts < 3:
        command = input("Enter packet command >> ").strip().lower()
        
        if command == "--s":
            print(f"\t{packet.protocol.upper()} packet(s) sent successfully")
            packet.send_packet()
            break
        elif command == "--sr":
            print(f"\t{packet.protocol.upper()} packet(s) sent successfully. Waiting for response...")
            
            start_time = time.time()
            packet.send_receive_packet()
            end_time = time.time()
            
            elapsed_ms = (end_time - start_time) * 1000
            print(f"\tResponse time: {elapsed_ms:.2f} ms")
            break
        elif command in ("help", "?"):
            print("\t--s / --sr")
        elif command == "exit":
            break
        else:
            if attempts + 1 < 3:
                print("\tError: Invalid command")
            attempts += 1
            
    else:
        print("\tError: Maximum attempts reached. Deleting packet...")
    
def main():
    while True:
        translated_data = parse_cli()
        if translated_data:
            translate_to_pkt(translated_data)
    
if __name__ == "__main__":
    main()
    