import os
import hmac
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def expand_key(key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=None,  # Salt is not used
        info=b'HKDF key expansion',
        backend=default_backend()
    )
    derived_key = hkdf.derive(key)
    return derived_key

def generate_hmac(key, message):
    h = hmac.new(key, message, sha256)
    return h.digest()

def verify_hmac(key, message, received_hmac):
    calculated_hmac = generate_hmac(key, message)
    return hmac.compare_digest(calculated_hmac, received_hmac)

def encrypt_message_aes(key, message):
    new_key = expand_key(key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    hmac_digest = generate_hmac(new_key, iv + ciphertext)
    # hexa bytes to ascii
    iv = iv.hex()
    ciphertext = ciphertext.hex()
    hmac_digest = hmac_digest.hex()
    # hexa to ascii
    
    return iv + ciphertext + hmac_digest

def decrypt_message_aes(key, ciphertext):
    new_key = expand_key(key)
    iv = ciphertext[:32]
    ciphertext = ciphertext[32:-64]
    received_hmac = ciphertext[-64:]
    iv = bytes.fromhex(iv)
    ciphertext = bytes.fromhex(ciphertext)
    received_hmac = bytes.fromhex(received_hmac)
    if not verify_hmac(new_key, iv + ciphertext, received_hmac):
        return False, "HMAC verification failed"
    else:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return True, plaintext.decode()