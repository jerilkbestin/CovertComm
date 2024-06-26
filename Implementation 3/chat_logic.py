from scapy.all import IP, TCP, send, Raw, AsyncSniffer
import random
import string
import hashlib
import encrypt_decrypt
import chat_communication
import socket
import threading



def password_to_aes_key(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    aes_key = sha256.digest()[:16]
    return aes_key



def encode_message_in_ip_header(message, target_ip, target_port, length):
    parts = [message[i:i+2] for i in range(0, len(message), 2)]
    chat_communication.chat_communicator(parts, target_ip, target_port, length)

# This class is used to process the messages received from the network to the front end
class MessageProcessor:
    def __init__(self, target_ip, listen_port, key, message_callback):
        self.whole_message = ""
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = key
        self.message_callback = message_callback

    def packet_callback(self, packet):
        status = True
        flags = str(packet[TCP].flags)
        
        # Define the flag values
        PA_ONLY = "PA"  # This combines PSH and ACK
        if packet.haslayer(IP) and packet[IP].src == self.target_ip and packet.haslayer(TCP) and packet[TCP].dport == self.listen_port:

            # reply to the sniffed packet with acknowledgement
            ip = IP(dst=self.target_ip, src=packet[IP].dst)
            tcp_ack = TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + 1)
            send(ip/tcp_ack, verbose=False)
            if flags==PA_ONLY:
            # Process packets with data and potential additional flags like PSH
              
                message_part = self.decode_message_from_ip_header(packet)
                if message_part:
                    self.whole_message += message_part
                    if self.whole_message.endswith("\x00"):
                        status, decrypted_message = self.message_decryptor()
                        
                        # if the message is compromised or password is wrong, status is "False" then display the message in the else part, else display the decrypted message
                        if status:
                            self.message_callback(decrypted_message)
                        else:
                            self.message_callback("CHAT HAS BEEN COMPROMISED. PLEASE RESTART OR DISCONNECT THE CHAT.")
            # if flags was fin then close the connection by sending a fin ack packet
            elif flags=="FA":
                ip = IP(dst=self.target_ip, src=packet[IP].dst)
                tcp_ack = TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="FA", seq=packet[TCP].ack+1, ack=packet[TCP].seq + 2)
                send(ip/tcp_ack, verbose=False)

    # decode the message from the ip header
    def decode_message_from_ip_header(self, packet):
        ident = packet[IP].id
        try:
            part = ident.to_bytes(2, 'big').decode()
            return part
        except:
            return ""

    # decrypt the final ciphertext to message
    def message_decryptor(self):
        decrypted_message = encrypt_decrypt.decrypt_message_aes(self.key, self.whole_message[:-1])
        self.whole_message = ""
        return decrypted_message

#This is the code to bind a server to listen for incoming messages. This helps in making sure that the server doesn't drop our packets.
def start_server(listen_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', listen_port))
    server_socket.listen(5)
    print(f"Server listening on port {listen_port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection established with {addr}")
            try:
                # Continuously read data from the connection until it's closed
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        # If no data is received, the client has closed the connection
                        break
                print(f"Connection closed with {addr}")
            finally:
                client_socket.close()
    finally:
        server_socket.close()
        print("Server closed.")

def start_sniffing(interface, listen_port, processor):
    # Run server in a separate thread to avoid blocking this function
    server_thread = threading.Thread(target=start_server, args=(listen_port,))
    server_thread.daemon = True  # Make the thread daemon so it exits with the main program
    server_thread.start()

    # Sniffer for sniffing packets for the chat
    filter_rule = f"ip src {processor.target_ip} and tcp dst port {listen_port}"

    sniffer = AsyncSniffer(iface=interface, filter=filter_rule, prn=processor.packet_callback, store=False)
    sniffer.start()
    return sniffer