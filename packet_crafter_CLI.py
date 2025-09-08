from packet_crafter_logic import *

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
        
def parse_cli():
    while True:
        user_input = input(">> ")
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
            print("Error: unclosed quotes in input")
            continue
        
        index = 0
        while index < len(tokens):
            command = tokens[index]
            
            if command in translation:
                try:
                    value = tokens[index + 1]
                    if value.startswith("-") and value in translation:
                        print(f"Error: Missing value for {command}")
                        break
                    
                    input_translated[translation[command]] = value
                    index += 2
                except IndexError:
                    print(f"Error: Missing value for {command}")
                    break
            else:
                print(f"Error: Unknown command: {command}")
                break
        else:
            return input_translated
        
def parse_payload(payload: str) -> str:
    if not (payload.startswith('"') and payload.endswith('"')):
        raise ValueError("Error: payload must be surrounded in quotation marks")
    return payload.strip('"')
        
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
                        raise ValueError("Error: Protocol required")
                    validate_mac(key, protocol)
                case "flags":
                    if protocol == None:
                        raise ValueError("Error: Protocol required")
                    validate_tcp_flags(key, protocol)
                case "dst_port" | "src_port":
                    if protocol == None:
                        raise ValueError("Error: Protocol required")
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
                print(f"Invalid integer for {field}")
                return
    
    try:
        pkt = Packet(**translated_data)
        print(f"Packet created successfully: {pkt}")
    except Exception as e:
        print(e)
    
def main():
    while True:
        translated_data = parse_cli()
        if translated_data:
            translate_to_pkt(translated_data)
    
if __name__ == "__main__":
    main()
    