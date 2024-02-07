from scapy.all import sniff, IP, TCP
from pyfiglet import figlet_format
from termcolor import cprint
import sys

def decode_message_from_ip_header(packet):
    if packet.haslayer(IP):
        # Extracting Identification field
        ident = packet[IP].id
        try:
            # Decoding back to string
            part = ident.to_bytes(2, 'big').decode()
            return part
        except:
            return ""

def packet_callback(packet):
    message_part = decode_message_from_ip_header(packet)
    
    # Added check to avoid any empty packets
    if packet.haslayer(IP):
        ident = packet[IP].id

        # Check if the Identification field is empty or zero, then return early
        if ident == 0:
            return 
    if packet.haslayer(TCP) and message_part:   # Handle exception that occurs when there is no TCP load
        try:
            cprint(figlet_format("BOB: " + message_part, font="starwars"), 'red', attrs=['bold'])
            payload = packet[TCP].payload
            ascii_payload = payload.load.decode('ascii', errors='replace')
            cprint(figlet_format("EVE: " + ascii_payload, font="cyberlarge"), 'yellow', attrs=['bold'])
        except AttributeError:
            print("No TCP Payload")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: BOB.py <network_adapter>")
        sys.exit(1)

    nic = sys.argv[1]
    # Live capture, filtering for IP packets
    try:
        sniff(iface=nic,filter="ip", prn=packet_callback) # Specified the network interface to capture properly, and limit only to IP packets
    except Exception as e:
        print(f"A scapy error occurred: {e}")