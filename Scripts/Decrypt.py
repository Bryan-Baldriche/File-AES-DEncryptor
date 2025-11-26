import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Encrypt import derive_key, SALT_LENGTH, NONCE_LENGTH

### Load the encrypted file data

def load_encrypted_file(input_path: str) -> bytes:
    with open(input_path, "rb") as enc_file:
        data = enc_file.read()
    return data
    
### Base64 Decoding 

def optional_base64_decode (data: bytes, Base64_input: bool) -> bytes:
    if not Base64_input:
        return data
    return Base64.b64decode(data)
    
### Get Salt, Nonce, and Encrypted data

def get_salt_nonce_ciphertext(data: bytes):
    salt = data[:SALT_LENGTH]
    nonce = data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    ciphertext = data[SALT_LENGTH + NONCE_LENGTH:]
    
    return salt, nonce, ciphertext
    
