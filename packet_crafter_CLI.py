from packet_crafter_logic import Packet

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
        
def parse_cli(user_input = get_user_input()):
    if user_input is None:
        user_input = get_user_input()
    
    input_list = user_input.split()
    input_translated = {}
    index = 0
    
    while index < len(input_list):
        command = input_list[index]
        
        if command in translation:
            try:
                value = input_list[index + 1]
                input_translated[translation[command]] = value
                index += 2
            except IndexError:
                print(f"Missing value for {command}")
        else:
            print(f"Unknown command {command}")
            index += 1
    
    return input_translated
    
def main():
    parse_cli()
    
if __name__ == "__main__":
    main()
    