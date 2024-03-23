#!/usr/bin/env python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt_message_aes(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    # hexa bytes to ascii
    iv = iv.hex()
    ciphertext = ciphertext.hex()
    # hexa to ascii
    
    return iv + ciphertext

def decrypt_message_aes(key, ciphertext):
    iv = ciphertext[:32]
    ciphertext = ciphertext[32:]
    iv = bytes.fromhex(iv)
    ciphertext = bytes.fromhex(ciphertext)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()