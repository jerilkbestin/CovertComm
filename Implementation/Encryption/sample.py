import encrpt_decrpt

# Generate key
key = b'\xb7\x8f\x1f\xa2}/\xc1\xc9E\xbe\xc7\xcc\x10\x0bz\x9c'

# Encrypt a message
message = "Hello, world!"
encrypted_message = encrpt_decrpt.encrypt_message_aes(key, message)
print("Encrypted message:", encrypted_message)

# Decrypt the message
decrypted_message = encrpt_decrpt.decrypt_message_aes(key, encrypted_message)
print("Decrypted message:", decrypted_message)
