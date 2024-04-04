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
        
        master.title("Secure Chat")
        
        self.chat_log = scrolledtext.ScrolledText(master, state='disabled')
        self.chat_log.grid(row=0, column=0, columnspan=2)
        
        self.msg_entry = tk.Entry(master)
        self.msg_entry.grid(row=1, column=0)
        
        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1)
        
        self.processor = MessageProcessor(target_ip, listen_port, self.key, self.display_message)
        self.sniffer_thread = Thread(target=start_sniffing, args=(interface, listen_port, self.processor), daemon=True)
        self.sniffer_thread.start()
        
    def send_message(self):
        message = self.msg_entry.get()
        if message:
            ciphertext = encrypt_decrypt.encrypt_message_aes(self.key, message)
            encode_message_in_ip_header(ciphertext + "\x00", self.target_ip, self.listen_port)
            self.msg_entry.delete(0, tk.END)
    
    def display_message(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chat_gui.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    root = tk.Tk()
    app = ChatGUI(root, sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
    root.mainloop()
