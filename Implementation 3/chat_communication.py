from scapy.all import IP, TCP, send, Raw, sr1
import random
import string
import logger_module
import time

def generate_random_payload():
    min_length = 1
    max_length = 28
    length = random.randint(min_length, max_length)
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def chat_communicator(parts, target_ip, target_port, length):

    # Set up IP and TCP layers for the SYN
    ip = IP(dst=target_ip)
    srcport = random.randint(1024, 65535)
    tcp_syn = TCP(dport=target_port, sport=srcport, flags="S", seq=1000)

    # Send SYN and get SYN-ACK
    syn_ack = sr1(ip/tcp_syn)

    # Send ACK for SYN-ACK
    ack = TCP(sport=syn_ack[TCP].dport, dport=target_port, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(ip/ack)

    # Send data after the handshake
    # data = "Here is some data to send after the handshake"
    # tcp_data = TCP(sport=syn_ack[TCP].dport, dport=target_port, flags='PA', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    # send(ip/tcp_data/Raw(load=data))
    next_seq= syn_ack[TCP].ack + 1
    ack= syn_ack[TCP].seq + 1
    starttime = time.time()
    for part in parts:
            ident = int.from_bytes(part.encode(), 'big')
            payload = generate_random_payload()
            # srcport = random.randint(1024, 65535)
            try:
                packet = IP(dst=target_ip, id=ident) / TCP(sport=syn_ack[TCP].dport, dport=target_port, flags='PA', seq=next_seq, ack=ack) / Raw(load=payload)
                send(packet, verbose=False)
                # Increment sequence number by data length for the next segment
                next_seq = next_seq + len(payload)
                ack=ack+1
            except Exception as e:
                print(f"Error sending packet: {e}")


    # Send FIN to gracefully close the connection
    tcp_fin = TCP(sport=syn_ack[TCP].dport, dport=target_port, flags='FA', seq=next_seq, ack=ack)
    fin_ack = sr1(ip/tcp_fin, verbose=False)

    # Respond to the server's FIN
    tcp_ack_fin = TCP(sport=syn_ack[TCP].dport, dport=22, flags='A', seq=fin_ack[TCP].ack, ack=fin_ack[TCP].seq + 1)
    send(ip/tcp_ack_fin, verbose=False)
    endtime = time.time()
    time_difference=endtime-starttime
    logger_module.logger(time_difference, length)

