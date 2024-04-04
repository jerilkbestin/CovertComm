import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from chat_logic import password_to_aes_key, encode_message_in_ip_header, MessageProcessor, start_sniffing
import encrypt_decrypt

class SnifferThread(QThread):
    new_message_signal = pyqtSignal(str)

    def __init__(self, interface, listen_port, processor):
        super().__init__()
        self.interface = interface
        self.listen_port = listen_port
        self.processor = processor

    def run(self):
        start_sniffing(self.interface, self.listen_port, self.processor)

class ChatGUI(QMainWindow):
    def __init__(self, interface, target_ip, listen_port, password):
        super().__init__()
        self.interface = interface
        self.target_ip = target_ip
        self.listen_port = listen_port
        self.key = password_to_aes_key(password)

        self.initUI()

        self.processor = MessageProcessor(target_ip, listen_port, self.key, self.display_message)
        self.sniffer_thread = SnifferThread(interface, listen_port, self.processor)
        self.sniffer_thread.new_message_signal.connect(self.display_message)
        self.processor.message_callback = self.sniffer_thread.new_message_signal.emit
        self.sniffer_thread.start()

    def initUI(self):
        self.setWindowTitle("CovertComms Chat")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.chat_log = QTextEdit(self)
        self.chat_log.setReadOnly(True)
        layout.addWidget(self.chat_log)

        self.msg_entry = QLineEdit(self)
        layout.addWidget(self.msg_entry)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def send_message(self):
        message = self.msg_entry.text()
        if message:
            ciphertext = encrypt_decrypt.encrypt_message_aes(self.key, message)
            self.display_message("You: " + message)
            encode_message_in_ip_header(ciphertext + "\x00", self.target_ip, self.listen_port)
            self.msg_entry.clear()

    def display_message(self, message):
        self.chat_log.append(message)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chat_gui.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    app = QApplication(sys.argv)
    gui = ChatGUI(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
    gui.show()
    sys.exit(app.exec_())
