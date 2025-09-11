"""
DISCLAIMER: This program is intended for educational purposes only. It must NOT be used maliciously
for activities such as probing, flooding, scanning, or any unauthorized network access. Always use
this tool within a controlled environment such as a private lab network or virtual environment.

This program is a basic packet crafter that supports TCP, UDP, ICMP, and ARP protocols. When ran, it opens
a prompt that allows users to create and send packets at the command line using specific commands. This
program allows sending a capped number of packets at once with a specified destination MAC address for Layer
2 traffic, as well as destination IPv4 addresses for Layer 3 traffic. It also supports crafting packets with
payloads, spoofed source IPv4 addresses, source ports, and MAC addresses. All packet information and responses
sent through this tool will also be logged into a separate SQL database with hashed IPv4 addresses, MAC
addresses, and payloads.

Author: Noah Cosamano
"""

import time
import sys
from field_validation import *
from packet_logic import create_packet, send_packet, send_receive_packet

COMMAND_TO_FIELD = {
    "-p": "protocol",
    "-dip": "dst_ip",
    "-sip": "src_ip",
    "-dp": "dst_port",
    "-sp": "src_port",
    "-dm": "dst_mac",
    "-sm": "src_mac",
    "-f": "flags",
    "-np": "num_pkts",
    "-pl": "payload",
    "-op": "arp_op",
}

COMMAND_TO_USE = {
    "? / help": "Displays all commands",
    "exit": "Exits the program",
    "--s": "Sends packet after packet has been created",
    "--sr": "Sends packet and waits for reply after packet has been created",
    "(command) ?": "Lists all options for command, (eg. -p ?)",
    "-p": "Protocol",
    "-dip": "Destination IPv4",
    "-sip": "Source IPv4",
    "-dp": "Destination port",
    "-sp": "Source port",
    "-dm": "Destination MAC",
    "-sm": "Source MAC",
    "-f": "Flags",
    "-np": "Number of packets",
    "-pl": "Payload",
    "-op": "ARP operator",
}


def get_user_input_lower():
    """
    Handles user input from the CLI, showing help or exiting if needed.

    Returns:
        str: The user's input in lowercase, unless it's a special command.
    """
    while True:
        user_input_lower = input(">> ").strip().lower()

        if user_input_lower in ("help", "?"):
            for command, use in COMMAND_TO_USE.items():
                print(f"  {command} -> {use}")

        elif user_input_lower == "exit":
            sys.exit()

        else:
            return user_input_lower


def command_helper(command):
    """
    Displays usage information for a specific CLI command.

    Args:
        command (str): CLI command flag (e.g. "-p", "-f").
    """
    match command:
        case "-p":
            for protocol in VALID_PROTOCOLS:
                print(f"  {protocol}")
        case "-dip" | "-sip":
            print(" x.x.x.x, x = 1-255, (eg. 192.168.52.3)")
        case "-dp" | "-sp":
            print(" 1-65535")
        case "-dm" | "-sm":
            print(" x:x:x:x:x:x, x = 1-9 a-F, (eg. a5:6e:f0:b3:e8:98)")
        case "-f":
            for flag in VALID_TCP_FLAGS:
                print(f" {flag}")
        case "-np":
            print(" 1-500")
        case "-pl":
            print(" any text")
        case "-op":
            print(" 1 or 2")


def parse_cli():
    """
    Parses the user's CLI input into structured field values.

    Returns:
        dict: A dictionary of field values derived from user input.
    """
    while True:
        user_input_lower = get_user_input_lower()
        if not user_input_lower:
            continue

        field_values = {}
        input_tokens = []
        in_quotes = False
        buffer = ""

        for input_part in user_input_lower.strip().split():
            if input_part.startswith('"') and not input_part.endswith('"'):
                in_quotes = True
                buffer = input_part[1:]
            elif in_quotes:
                if input_part.endswith('"'):
                    buffer += " " + input_part[:-1]
                    input_tokens.append(buffer)
                    buffer = ""
                    in_quotes = False
                else:
                    buffer += " " + input_part
            else:
                input_tokens.append(input_part)

        if in_quotes:
            print(" Error: Unclosed quotes in input")
            continue

        token_index = 0
        while token_index < len(input_tokens):
            command = input_tokens[token_index]

            if command in COMMAND_TO_FIELD:
                try:
                    command_value = input_tokens[token_index + 1]
                    if (
                        command_value.startswith("-")
                        and command_value in COMMAND_TO_FIELD
                    ):
                        print(f" Error: Missing value for {command}")
                        break

                    if command_value == "?":
                        command_helper(command)
                        break

                    field_values[COMMAND_TO_FIELD[command]] = command_value
                    token_index += 2
                except IndexError:
                    print(f" Error: Missing value for {command}")
                    break

            else:
                print(f" Error: Unknown command: {command}")
                break
        else:
            return field_values


def verify_field_values(field_values: dict):
    """
    Validates the parsed CLI field values.

    Args:
        field_values (dict): Dictionary of user-entered packet fields.

    Returns:
        bool: True if all fields are valid, False otherwise.
    """
    if "protocol" not in field_values:
        print(" Error: Protocol required")
        return False

    try:
        protocol = validate_protocol(field_values["protocol"])

        for field, value in field_values.items():
            match field.lower():
                case "protocol":
                    continue
                case "dst_ip" | "src_ip":
                    validate_ip(value)
                case "dst_mac" | "src_mac":
                    validate_mac(value, protocol)
                case "flags":
                    validate_tcp_flags(value, protocol)
                case "dst_port" | "src_port":
                    validate_port(value, protocol)
                case "num_pkts":
                    validate_num_pkts(value)
                case "arp_op":
                    validate_arp_op(value, protocol)
                case "payload":
                    validate_payload(value)

        return True

    except Exception as e:
        print(e)
        return False


def command_packet(packet, field_values):
    """
    Prompts the user to send the packet (with or without waiting for a reply).

    Args:
        packet: The scapy packet object to send.
        field_values (dict): The associated field values used to create the packet.
    """
    attempts = 0

    while attempts < 3:
        packet_command = input("Enter packet command >> ").strip().lower()

        if packet_command == "--s":
            send_packet(packet, field_values)
            break
        if packet_command == "--sr":
            print(" packet(s) sent successfully. Waiting for response...")

            start_time = time.time()
            send_receive_packet(packet, field_values)
            end_time = time.time()

            elapsed_ms = (end_time - start_time) * 1000
            print(f" Response time: {elapsed_ms:.2f} ms")
            break
        elif packet_command in ("help", "?"):
            print(" --s / --sr")
        elif packet_command == "exit":
            break
        else:
            if attempts + 1 < 3:
                print(" Error: Invalid command")
            attempts += 1

    else:
        print(" Error: Maximum attempts reached. Deleting packet...")


def main():
    """
    Main program loop. Continuously parses user input, validates it,
    creates the packet, and handles the send/send+reply interaction.
    """
    while True:
        field_values = parse_cli()
        if verify_field_values(field_values) is True:
            packet = create_packet(field_values)
            if packet:
                command_packet(packet, field_values)
        continue


if __name__ == "__main__":
    main()
