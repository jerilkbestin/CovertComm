import os
import hmac
import hashlib
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes



#generating hmac hash
def generate_hmac(key, message):
    h = hmac.new(key, message, hashlib.sha1)
    return h.digest()

#verifying hmac hash
def verify_hmac(key, message, received_hmac):
    calculated_hmac = generate_hmac(key, message)
    return hmac.compare_digest(calculated_hmac, received_hmac)

#encrypting message using AES
def encrypt_message_aes(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    hmac_digest = generate_hmac(key, iv + ciphertext)
    iv = iv.hex()
    ciphertext = ciphertext.hex()
    hmac_digest = hmac_digest.hex()
    # hexa to ascii
    
    return iv + ciphertext + "#"+ hmac_digest


#decrypting message using AES
def decrypt_message_aes(key, ciphertext):
    ciphertext = ciphertext.split("#")
    received_hmac = ciphertext[1]
    ciphertext = ciphertext[0]
    iv = ciphertext[:32]
    ciphertext = ciphertext[32:]
    iv = bytes.fromhex(iv)
    ciphertext = bytes.fromhex(ciphertext)
    received_hmac = bytes.fromhex(received_hmac)

    #verifying hmac hash
    #if not verified it will send the false as status
    if not verify_hmac(key, iv + ciphertext, received_hmac):
        return False, "HMAC verification failed"
    else:
        # calling AES decryptor
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return True, plaintext.decode()

#generating AES key from password
def password_to_aes_key(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    aes_key = sha256.digest()[:16]
    return aes_key


## Testing:
# # Example usage:
# key = password_to_aes_key('my_secret_key')
# message = "Hello, world!"
# encrypted_message = encrypt_message_aes(key, message)
# print(encrypted_message)
# encrypted_message_list = list(encrypted_message)
# encrypted_message_list[0] = '6'
# encrypted_message= ''.join(encrypted_message_list)
# print("Encrypted message:", encrypted_message)
# decrypted_message = decrypt_message_aes(key, encrypted_message)
# print("Decrypted message:", decrypted_message)