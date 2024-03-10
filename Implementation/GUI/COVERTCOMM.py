import tkinter as tk
import threading
import socket

class P2PChatApp:
    def __init__(self, username, port):
        self.username = username
        self.port = port

        self.root = tk.Tk()
        self.root.title(f"COVERTCOMM - {self.username}")

        self.text_area = tk.Text(self.root)
        self.text_area.pack(fill="both", expand=True)

        self.entry_field = tk.Entry(self.root)
        self.entry_field.pack(fill="x")

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(fill="x")

        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)

        while True:
            client_socket, client_address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                self.text_area.insert(tk.END, f"{message}\n")
                self.text_area.see(tk.END)
            except ConnectionResetError:
                break

    def send_message(self):
        message = self.entry_field.get()
        self.entry_field.delete(0, tk.END)

        for port in range(7001, 7010):  # Try connecting to ports 7001 to 7010
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect(('localhost', port))
                client_socket.send(f"{self.username}: {message}".encode('utf-8'))
                client_socket.close()
            except ConnectionRefusedError:
                continue

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    username = input("Enter your username: ")
    port = int(input("Enter port to listen on (7001-7010): "))
    app = P2PChatApp(username, port)
    app.run()
