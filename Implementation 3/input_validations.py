# input_validations.py

import os
import ipaddress
import string

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
        return 0 <= port <= 65535
    except ValueError:
        return False
    
def validate_password(password):
    """Validate the password length and ensure it contains only printable characters."""
    if not (8 <= len(password) <= 20):
        return False, "Error: Password must be between 8 and 20 characters."
    if not all(char in string.printable for char in password):
        return False, "Error: Password contains non-printable characters."
    return True, ""

def validate_all(interface, target_ip, listen_port_str, password):
    """Validate all inputs and return validation status and messages or validated values."""
    if not validate_network_adapter(interface):
        return False, "Error: Invalid interface."
    if not validate_ip_address(target_ip):
        return False, "Error: Invalid IP address."
    if not validate_port(listen_port_str):
        return False, "Error: Invalid port number. Port must be between 1024 and 65535."
    
    # Updated to handle the new return signature of validate_password
    password_valid, password_message = validate_password(password)
    if not password_valid:
        return False, password_message
    
    listen_port = int(listen_port_str)
    return True, (interface, target_ip, listen_port, password)

def validate_message_length(message, max_length=100):
    """Validate that the message does not exceed the max_length characters and contains only printable characters."""
    if len(message) > max_length:
        return False, f"Error: Message exceeds {max_length} characters. Your message was {len(message)} characters long."
    if not all(char in string.printable for char in message):
        return False, "Error: Message contains non-printable characters."
    return True, ""