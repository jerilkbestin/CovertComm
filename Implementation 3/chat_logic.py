from scapy.all import IP, TCP, send, Raw, AsyncSniffer
import random
import string
import sys
import encrypt_decrypt
import hashlib

# Function to generate AES key from password
def password_to_aes_key(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    aes_key = sha256.digest()[:16]  # Take the first 16 bytes (128 bits) of the hash
    return aes_key

# Function to generate random payload
def generate_random_payload():
    min_length = 1
    max_length = 28  # Adjusted for the lowest MTU possible minus the IP and TCP headers
    length = random.randint(min_length, max_length)
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

# Function to encode and send message
def encode_message_in_ip_header(message, target_ip, target_port):
    parts = [message[i:i+2] for i in range(0, len(message), 2)]
    for part in parts:
        ident = int.from_bytes(part.encode(), 'big')
        payload = generate_random_payload()
        srcport = random.randint(1024, 65535)
        try:
            packet = IP(dst=target_ip, id=ident) / TCP(sport=srcport, dport=target_port) / Raw(load=payload)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Error sending packet: {e}")

# Class to encapsulate message processing
class MessageProcessor:
    def __init__(self, target_ip, listen_port, key):
        self.whole_message = ""
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = key

    def packet_callback(self, packet):
        if packet.haslayer(IP) and packet[IP].src == self.target_ip and packet.haslayer(TCP) and packet[TCP].dport == self.listen_port:
            message_part = self.decode_message_from_ip_header(packet)
            if message_part:
                self.whole_message += message_part
                if self.whole_message.endswith("\x00"):  # Check for message termination
                    self.message_decryptor()

    def decode_message_from_ip_header(self, packet):
        ident = packet[IP].id
        try:
            part = ident.to_bytes(2, 'big').decode()
            return part
        except:
            return ""

    def message_decryptor(self):
        print("\n\nRECEIVED ENCRYPTED MESSAGE IS:", self.whole_message)
        decrypted_message = encrypt_decrypt.decrypt_message_aes(self.key, self.whole_message[:-2])
        print("\n\nRECEIVED DECRYPTED MESSAGE IS:", decrypted_message, "\n\nChat:")
        self.whole_message = ""  # Reset message buffer
        return decrypted_message

def start_sniffing(interface, listen_port, processor):
    filter_rule = f"ip src {processor.target_ip} and tcp dst port {listen_port}"
    sniffer = AsyncSniffer(iface=interface, filter=filter_rule, prn=processor.packet_callback, store=False)
    sniffer.start()
    return sniffer

def interactive_mode(interface, target_ip, listen_port, password):
    key = password_to_aes_key(password)
    processor = MessageProcessor(target_ip, listen_port, key)
    print("Enter your messages below (type 'exit' to quit):")
    sniffer = start_sniffing(interface, listen_port, processor)
    try:
        while True:
            message = input("\nChat:\n").strip()
            if message.lower() == 'exit':
                break
            ciphertext = encrypt_decrypt.encrypt_message_aes(key, message)
            print(f"\nSENT ENCRYPTED MESSAGE: {ciphertext}")
            encode_message_in_ip_header(ciphertext + "\x00", target_ip, listen_port)
    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        sniffer.stop()

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: script.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    nic = sys.argv[1]
    target_ip = sys.argv[2]
    listen_port = int(sys.argv[3])
    password = sys.argv[4]

    interactive_mode(nic, target_ip, listen_port, password)
