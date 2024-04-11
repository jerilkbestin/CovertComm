# input_validations.py

import os
import platform
import ipaddress
import subprocess
import string

def parse_macos_networksetup(output):
    """ Parse macOS networksetup output into a dictionary of devices and their hardware ports. """
    adapters = {}
    current_port = None

    for line in output.splitlines():
        if line.startswith("Hardware Port"):
            current_port = line.split(": ", 1)[1]
        elif line.startswith("Device") and current_port:
            device = line.split(": ", 1)[1]
            adapters[device] = current_port

    return adapters

def validate_network_adapter_darwin(adapter):
    """ Validate network adapter on macOS. """
    try:
        output = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        adapters = parse_macos_networksetup(output)
        return adapter in adapters
    except subprocess.CalledProcessError:
        return False

def validate_network_adapter_windows(adapter):
    """ Validate network adapter on Windows using PowerShell. """
    try:
        command = ["powershell", "-Command", "Get-NetAdapter | Format-Table -Property Name -HideTableHeaders"]
        output = subprocess.check_output(command, text=True)
        adapter_names = output.strip().split('\n')
        adapter_names = [name.strip() for name in adapter_names if name.strip()]  # Clean up the names
        return adapter in adapter_names
    except subprocess.CalledProcessError:
        return False

def validate_network_adapter(adapter):
    """ Validate network adapter based on the operating system. """
    os_type = platform.system()
    
    if os_type == "Linux":
        return os.path.exists(f"/sys/class/net/{adapter}")
    elif os_type == "Darwin":
        return validate_network_adapter_darwin(adapter)
    elif os_type == "Windows":
        return validate_network_adapter_windows(adapter)

    return False

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
        return False, "Error: Invalid port number. Port must be between 0 and 65535."
    
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