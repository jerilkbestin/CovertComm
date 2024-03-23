from scapy.all import IP, TCP, send, Raw, sniff, AsyncSniffer
import random
import string
import sys
import encrypt_decrypt

current_timer = None

# Generate key
key = b'\xb7\x8f\x1f\xa2}/\xc1\xc9E\xbe\xc7\xcc\x10\x0bz\x9c'

# Function to generate random payload
def generate_random_payload(length=5):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

# Function to encode and send message
def encode_message_in_ip_header(message, target_ip, target_port):
    parts = [message[i:i+2] for i in range(0, len(message), 2)]
    for part in parts:
        ident = int.from_bytes(part.encode(), 'big')
        payload = generate_random_payload()
        try:
            packet = IP(dst=target_ip, id=ident) / TCP(dport=target_port) / Raw(load=payload)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error sending packet: {e}")

# Function to decode message from IP header
def decode_message_from_ip_header(packet):
    ident = packet[IP].id
    try:
        part = ident.to_bytes(2, 'big').decode()
        return part
    except:
        return ""

whole_message = ""
# Callback function for sniffing
def packet_callback(packet):
    global current_timer
    global whole_message
    if packet.haslayer(IP) and packet[IP].src == target_ip and packet.haslayer(TCP) and packet[TCP].dport == listen_port:
        message_part = decode_message_from_ip_header(packet)
        if message_part:
            whole_message += message_part
            # if it ends with "#", then it is the last message
            if whole_message.endswith("#"):
                function_to_call()


def function_to_call():
    global whole_message
    print("\n\nRECEIVED ENCRYPTED MESSAGE IS:", whole_message[:-2])
    # decrypt message
    decrypted_message = encrypt_decrypt.decrypt_message_aes(key, whole_message[:-2])
    print("\n\nRECEIVED DECRYPTED MESSAGE IS:",decrypted_message, "\n\nChat:")
    whole_message = ""

# Function to start sniffing in a separate thread
def start_sniffing(interface, listen_port):
    filter_rule = f"ip src {target_ip} and tcp dst port {listen_port}"
    sniffer = AsyncSniffer(iface=interface, filter=filter_rule, prn=packet_callback, store=False)
    sniffer.start()
    return sniffer

# Main interactive function
def interactive_mode(interface, target_ip, listen_port):
    print("Enter your messages below (type 'exit' to quit):")
    sniffer = start_sniffing(interface, listen_port)
    try:
        while True:
            message = input("\nChat:\n").strip()
            if message.lower() == 'exit':
                break
            # Encrypt message
            ciphertext = encrypt_decrypt.encrypt_message_aes(key, message)
            print(f"\nSENT ENCRYPTED MESSAGE: {ciphertext}")
            encode_message_in_ip_header(ciphertext+"#", target_ip, listen_port)
    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        sniffer.stop()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: script.py <network_adapter> <target_ip> <listen_port>")
        sys.exit(1)

    nic = sys.argv[1]
    target_ip = sys.argv[2]
    listen_port = int(sys.argv[3])  # Convert the port argument to an integer
    interactive_mode(nic, target_ip, listen_port)