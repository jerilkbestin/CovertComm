from scapy.all import IP, TCP, send, Raw
import random
import string
import sys

def generate_random_payload(length=5): # Adding random ASCII characters to the payload, just to confuse EVE!
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def encode_message_in_ip_header(message, target_ip):
    # Splitting message into parts that fit into the Identification field
    # Assuming each char is one byte and IP Identification field is 16 bits
    parts = [message[i:i+2] for i in range(0, len(message), 2)]

    for part in parts:
        # Convert part to integer for Identification field
        ident = int.from_bytes(part.encode(), 'big')    # Big Endian for correct placement of chars
        payload = generate_random_payload()

        try:    # In case of a wrong/unreachable IP address
            packet = IP(dst=target_ip, id=ident) / TCP() / Raw(load=payload)
            send(packet)
        except Exception as e:
            print(f"Error sending packet: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ALICE.py <target_ip> <message>")
        sys.exit(1)

    target_ip = sys.argv[1]
    message = sys.argv[2]
    encode_message_in_ip_header(message, target_ip)