from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import threading
import sys
from chat_logic import password_to_aes_key, encode_message_in_ip_header, MessageProcessor, start_sniffing
import encrypt_decrypt
from input_validations import validate_all

def display_message(message, received=False):
    """
    Display the message in the console.
    Prefix 'Them: ' for received messages.
    """
    print(f"\r{'Them: ' if received else 'You: '}{message}")

def send_message(session, interface, target_ip, target_port, key):
    """
    Use prompt_toolkit's session.prompt() to handle input.
    This allows asynchronous message display without interrupting user input.
    """
    while True:
        try:
            # The patch_stdout context manager allows other threads to write to stdout
            # without interfering with the input buffer.
            with patch_stdout():
                message = session.prompt("> ").strip()
            if message.lower() == "exit":
                print("Exiting chat...")
                break
            if message:  # Don't process empty messages
                ciphertext = encrypt_decrypt.encrypt_message_aes(key, message)
                encode_message_in_ip_header(ciphertext + "\x00", target_ip, target_port)
                # No need to manually display "You: message" because prompt_toolkit handles it.
        except KeyboardInterrupt:
            print("\nExiting chat...")
            break

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chat_frontend_cli.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    validation_passed, result = validate_all(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

    if not validation_passed:
        print(result)  # result contains the error message
        sys.exit(1)

    # Unpack the validated and converted arguments
    interface, target_ip, listen_port, password = result

    key = password_to_aes_key(password)

    processor = MessageProcessor(target_ip, int(listen_port), key, lambda msg: display_message(msg, True))
    sniffer_thread = threading.Thread(target=lambda: start_sniffing(interface, int(listen_port), processor), daemon=True)
    sniffer_thread.start()

    # Create a PromptSession instance for managing console input.
    session = PromptSession()
    send_message(session, interface, target_ip, int(listen_port), key)