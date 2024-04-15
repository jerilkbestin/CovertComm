from scapy.all import IP, TCP, send, Raw, AsyncSniffer
import random
import string
import hashlib
import encrypt_decrypt

def password_to_aes_key(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    aes_key = sha256.digest()[:16]
    return aes_key

def generate_random_payload():
    min_length = 1
    max_length = 28
    length = random.randint(min_length, max_length)
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

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

class MessageProcessor:
    def __init__(self, target_ip, listen_port, key, message_callback):
        self.whole_message = ""
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = key
        self.message_callback = message_callback

    def packet_callback(self, packet):
        status = True
        if packet.haslayer(IP) and packet[IP].src == self.target_ip and packet.haslayer(TCP) and packet[TCP].dport == self.listen_port:
            message_part = self.decode_message_from_ip_header(packet)
            if message_part:
                self.whole_message += message_part
                if self.whole_message.endswith("\x00"):
                    status, decrypted_message = self.message_decryptor()
                    
                    if status:
                        self.message_callback(decrypted_message)
                    else:
                        self.message_callback(status+"CHAT HAS BEEN COMPROMISED. PLEASE RESTART OR DISCONNECT THE CHAT.")

    def decode_message_from_ip_header(self, packet):
        ident = packet[IP].id
        try:
            part = ident.to_bytes(2, 'big').decode()
            return part
        except:
            return ""

    def message_decryptor(self):
        decrypted_message = encrypt_decrypt.decrypt_message_aes(self.key, self.whole_message[:-2])
        self.whole_message = ""
        return decrypted_message

def start_sniffing(interface, listen_port, processor):
    filter_rule = f"ip src {processor.target_ip} and tcp dst port {listen_port}"
    sniffer = AsyncSniffer(iface=interface, filter=filter_rule, prn=processor.packet_callback, store=False)
    sniffer.start()
    return sniffer