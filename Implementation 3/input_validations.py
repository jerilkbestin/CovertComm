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