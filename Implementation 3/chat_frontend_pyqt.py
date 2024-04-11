import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from chat_logic import password_to_aes_key, encode_message_in_ip_header, MessageProcessor, start_sniffing
import encrypt_decrypt
from input_validations import validate_all, validate_message_length


class SnifferThread(QThread):
    # Updated signal to include a flag indicating if the message is received
    new_message_signal = pyqtSignal(str, bool)

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

        # Pass a lambda to prepend "Them: " for received messages
        self.processor = MessageProcessor(target_ip, listen_port, self.key, lambda msg: self.display_message(msg, True))
        self.sniffer_thread = SnifferThread(interface, listen_port, self.processor)
        self.sniffer_thread.new_message_signal.connect(lambda msg, received: self.display_message(msg, received))
        self.sniffer_thread.start()

    def initUI(self):
        self.setWindowTitle("CovertComm Chat")
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
            # Validate message length and content
        valid_length, error_message = validate_message_length(message)
        if not valid_length:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Message Error", error_message)
            return  # Do not proceed with sending the message
        if message:
            ciphertext = encrypt_decrypt.encrypt_message_aes(self.key, message)
            # Explicitly specify 'received=False' for sent messages
            self.display_message("You: " + message, False)
            encode_message_in_ip_header(ciphertext + "\x00", self.target_ip, self.listen_port)
            self.msg_entry.clear()

    # Updated to prepend "Them: " for received messages based on the 'received' flag
    def display_message(self, message, received=False):
        prefix = "Them: " if received else ""
        self.chat_log.append(prefix + message)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chat_frontend_pyqt.py <network_adapter> <target_ip> <listen_port> <password>")
        sys.exit(1)

    validation_passed, result = validate_all(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

    if not validation_passed:
        print(result)  # result contains the error message
        sys.exit(1)

    # Unpack the validated and converted arguments
    interface, target_ip, listen_port, password = result
    app = QApplication(sys.argv)
    gui = ChatGUI(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])
    gui.show()
    sys.exit(app.exec_())