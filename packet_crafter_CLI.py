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

def get_user_input():
    return input(">> ")
        
def parse_cli():
    while True:
        user_input = get_user_input()
        
        if user_input is None:
            continue
        
        input_list = user_input.split()
        input_translated = {}
        index = 0
        
        while index < len(input_list):
            command = input_list[index]
            
            if command in translation:
                try:
                    value = input_list[index + 1]
                    if value in translation:
                        raise ValueError(f"Missig value for {command}")
                    input_translated[translation[command]] = value
                    index += 2
                except ValueError:
                    print(f"Missing value for {command}")
                    break
            else:
                print(f"Unknown command: {command}")
                break
            
        else:
            return input_translated
        
def verify_field(translated_data: dict):
    try:
        for item, key in translated_data.items():
            match item.lower():
                case "protocol":
                    validate_protocol(key)
                case "dst_ip" | "src_ip":
                    validate_ip(key)
                case "dst_mac" | "src_mac":
                    validate_mac(key)
                case "flags":
                    validate_tcp_flags(key)
                case "dst_port" | "src_port":
                    validate_port(key)
                case "num_pkts":
                    validate_num_pkts(key)
                case "arp_op":
                    validate_arp_op(key)
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
        print(f"Error creating packet: {e}")
    
def main():
    while True:
        translated_data = parse_cli()
        if translated_data:
            translate_to_pkt(translated_data)
    
if __name__ == "__main__":
    main()
    