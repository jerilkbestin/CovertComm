from scapy.all import IP, TCP, send, Raw, AsyncSniffer
import random
import string
import hashlib
import encrypt_decrypt
import chat_communication
import socket

def password_to_aes_key(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    aes_key = sha256.digest()[:16]
    return aes_key



def encode_message_in_ip_header(message, target_ip, target_port):
    parts = [message[i:i+2] for i in range(0, len(message), 2)]
    chat_communication.chat_communicator(parts, target_ip, target_port)

class MessageProcessor:
    def __init__(self, target_ip, listen_port, key, message_callback):
        self.whole_message = ""
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = key
        self.message_callback = message_callback

    def packet_callback(self, packet):
        status = True
        flags = packet[TCP].flags
        if packet.haslayer(IP) and packet[IP].src == self.target_ip and packet.haslayer(TCP) and packet[TCP].dport == self.listen_port:
            if not (flags & 0x02 or flags & 0x01 or flags & 0x10):  # SYN, FIN, or sole ACK
            # Process packets with data and potential additional flags like PSH
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
        decrypted_message = encrypt_decrypt.decrypt_message_aes(self.key, self.whole_message[:-1])
        self.whole_message = ""
        return decrypted_message

def start_server(listen_port):
    # Create a socket object using IPv4 and TCP protocol
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a public host, and a well-known port
    server_socket.bind(('', listen_port))  # '' means all available interfaces

    # Become a server socket
    server_socket.listen(5)  # Allows up to 5 unaccepted connections before refusing new ones

    print(f"Server listening on port {listen_port}")

def start_sniffing(interface, listen_port, processor):
    start_server(listen_port)
    filter_rule = f"ip src {processor.target_ip} and tcp dst port {listen_port}"
    sniffer = AsyncSniffer(iface=interface, filter=filter_rule, prn=processor.packet_callback, store=False)
    sniffer.start()
    return sniffer