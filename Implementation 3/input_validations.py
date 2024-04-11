# input_validations.py

import os
import ipaddress

def validate_network_adapter(adapter):
    # For Unix/Linux systems, adapt for Windows if needed
    return os.path.exists(f"/sys/class/net/{adapter}")

def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port):
    try:
        port = int(port)
        return 1024 <= port <= 65535
    except ValueError:
        return False

def validate_password(password):
    return 8 <= len(password) <= 20

def validate_all(interface, target_ip, listen_port_str, password):
    if not validate_network_adapter(interface):
        return (False, "Error: Invalid interface.")
    if not validate_ip_address(target_ip):
        return (False, "Error: Invalid IP address.")
    if not validate_port(listen_port_str):
        return (False, "Error: Invalid port number. Port must be between 1024 and 65535.")
    if not validate_password(password):
        return (False, "Error: Password must be between 8 and 20 characters.")
    
    # If all validations pass, convert listen_port_str to int and return all values
    listen_port = int(listen_port_str)
    return (True, (interface, target_ip, listen_port, password))
