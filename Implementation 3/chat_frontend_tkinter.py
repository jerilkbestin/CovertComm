import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import sys
from chat_logic import password_to_aes_key, encode_message_in_ip_header, MessageProcessor, start_sniffing
import encrypt_decrypt

class ChatGUI:
    def __init__(self, master, interface, target_ip, listen_port, password):
        self.master = master
        self.interface = interface
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = password_to_aes_key(password)
        
        master.title("CovertComms Chat")

        # Center-align the chat log and make it occupy most of the window
        self.chat_log = scrolledtext.ScrolledText(master, state='disabled', width=60, height=20)
        self.chat_log.pack(padx=20, pady=20)

        # Frame for entry and button to be centered together
        self.entry_frame = tk.Frame(master)
        self.entry_frame.pack(pady=10)

        self.msg_entry = tk.Entry(self.entry_frame, width=53)
        self.msg_entry.pack(side=tk.LEFT, padx=(0, 10))

        self.send_button = tk.Button(self.entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        self.processor = MessageProcessor(target_ip, listen_port, self.key, self.display_message)
        self.sniffer_thread = Thread(target=lambda: start_sniffing(interface, listen_port, self.processor), daemon=True)
        self.sniffer_thread.start()
        
    def send_message(self):
        message = self.msg_entry.get()
        if message:
            ciphertext = encrypt_decrypt.encrypt_message_aes(self.key, message)
            encode_message_in_ip_header(ciphertext + "\x00", self.target_ip, self.listen_port)
            self.display_message(f"You: {message}", sent=True)
            self.msg_entry.delete(0, tk.END)
    
    def display_message(self, message, sent=False):
        if not sent:
            message = f"Them: {message}"
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.yview(tk.END)  # Auto-scroll to the bottom
        self.chat_log.config(state='disabled')

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chat_frontend_tkinter.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    root = tk.Tk()
    app = ChatGUI(root, sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
    root.mainloop()