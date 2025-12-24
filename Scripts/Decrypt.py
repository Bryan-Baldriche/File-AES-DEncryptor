import base64
import os
import pathlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Encrypt import derive_key, SALT_LENGTH, NONCE_LENGTH
from Encrypt import HEADER_MAGIC

### Load the encrypted file data

def load_encrypted_file(input_path: str) -> bytes:
    with open(input_path, "rb") as enc_file:
        data = enc_file.read()
    return data
    
### Base64 Decoding 

def optional_base64_decode (data: bytes, Base64_input: bool) -> bytes:
    if not Base64_input:
        return data
    return base64.b64decode(data)
    
### Get Salt, Nonce, and Encrypted data

def get_salt_nonce_ciphertext(data: bytes):
    salt = data[:SALT_LENGTH]
    nonce = data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    ciphertext = data[SALT_LENGTH + NONCE_LENGTH:]
    
    return salt, nonce, ciphertext

### AES Decrypt

def aes_decrypt(ciphertext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

### Get unscrambled name 

def extract_filename_header(plaintext:bytes):
    if not plaintext.startswith(HEADER_MAGIC):
        return None, plaintext
        
    idx = len(HEADER_MAGIC)
    
    name_len = int.from_bytes(plaintext[idx:idx+2], "big")
    idx +=2
    
    filename = plaintext[idx:idx+name_len].decode("utf-8")
    idx += name_len
    
    remaining = plaintext[idx:]
    
    return filename, remaining

def get_output_filename(output_path: str, restored_name: str | None) -> pathlib.Path:
    
    out_path = pathlib.Path(output_path)

    if restored_name is None:
        return out_path

    if out_path.is_dir() or output_path.endswith(("/","\\")):
        return out_path / restored_name

    return out_path.parent / restored_name

def atomic_write(output_path: pathlib.Path, data: bytes) -> pathlib.Path:
    out_dir = output_path.parent
    temp = out_dir / (output_path.name + ".tmp_" + secrets.token_hex(8))

    with temp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    os.replace(temp, output_path)
    return output_path

def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    base64_input: bool = False,
    restore_name: bool = False
) -> pathlib.Path:

    encrypted_data = load_encrypted_file(input_path)

    encrypted_data = optional_base64_decode(encrypted_data, base64_input)

    salt, nonce, ciphertext = get_salt_nonce_ciphertext(encrypted_data)

    plaintext = aes_decrypt(ciphertext, password, salt, nonce)

    restored_filename = None
    file_data = plaintext

    if restore_name:
        restored_filename, file_data = extract_filename_header(plaintext)

    final_output_path = get_output_filename(output_path, restored_filename)

    final_output_path.parent.mkdir(parents=True, exist_ok=True)

    atomic_write(final_output_path, file_data)

    return final_output_path
