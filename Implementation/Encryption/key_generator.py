import os

def generate_128_bit_key():
    return os.urandom(16)

# Example usage
key = generate_128_bit_key()
print("128-bit key:", key)
