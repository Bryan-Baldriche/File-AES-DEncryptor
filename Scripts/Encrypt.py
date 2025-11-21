import os
import base64
import shutil
import tempfile
import pathlib
import secrets
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

### CRYPTO CONSTANTS

KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
PBKDF2_ITERATIONS = 400000
ZIP_TEMP_PREFIX = "ENC_TEMP_"
HEADER_MAGIC = b"FN1\0"

### derive 256-bit key

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = KEY_LENGTH,
        salt = salt,
        iterations = PBKDF2_ITERATIONS,
    )

    key = kdf.derive(password_bytes)
    return key

### Detect file/directory and zip if directory

def prepare_input_file(input_path: str) -> tuple[pathlib.Path, pathlib.Path | None]:
    path_to_file = pathlib.Path(input_path)

    if path_to_file.is_file():
        return path_to_file, None
    if not path_to_file.is_dir():
        raise ValueError(f"Input path is neither a file nor directory: {input_path}")

    # make temp directory for zip
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix=ZIP_TEMP_PREFIX))
    zip_path = temp_dir / (path_to_file.name +".zip")

    # to make a non-compressed zip for file integrity

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as z:
        for file_path in path_to_file.rglob("*"):
            if file_path.is_file():
                z.write(
                    file_path,
                    file_path.relative_to(path_to_file)
                )

    return zip_path, temp_dir

### load plaintext

def load_plaintext(file_path: pathlib.Path) -> bytes:
    with file_path.open("rb") as user_file:
        data = user_file.read()
    return data

### embed filename header if --scramble-name is used

def embed_filename_header(
        plaintext: bytes,
        input_path: pathlib.Path,
        add_header: bool
) -> bytes:

    if not add_header:
        return plaintext

    original_name = input_path.name
    name_bytes = original_name.encode("utf-8")

    if len(name_bytes) > 65535:
        raise ValueError("Filename too long to store in header (maximum is 65535 bytes).")

    name_len = len(name_bytes).to_bytes(2,"big")

    # Construct header

    return HEADER_MAGIC + name_len + name_bytes + plaintext

### Salt and Nonce Generation

def generate_salt_and_nonce() -> tuple[bytes, bytes]:
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    return salt, nonce

### AES Encryption Time

def aes_encrypt(plaintext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext

### base64 optional encoding

def optional_base64_encode(data: bytes, base64_output: bool) -> bytes:
    if not base64_output:
        return data

    return base64.b64encode(data)

### Output filename determination / scrambled or not

def determine_scramble(output_path: str, scramble_name: bool) -> pathlib.Path:
    outward_path = pathlib.Path(output_path)

    if not scramble_name:
        return outward_path

    if not outward_path.exists():
        outward_path.mkdir(parents=True, exist_ok=True)
    elif not outward_path.is_dir():
        outward_path = outward_path.parent

    random_scramble = secrets.token_hex(16) +".enc"

    return outward_path / random_scramble

### atomic output

def atomic_output(output_path: pathlib.Path, data:bytes) -> pathlib.Path:
    output_dir = output_path.parent
    temporfile = output_dir / (output_path.name + ".tmp_" + secrets.token_hex(8))

    with temporfile.open("wb") as outfile:
        outfile.write(data)
        outfile.flush()
        os.fsync(outfile.fileno())

    os.replace(temporfile, output_path)

    return output_path

### tempfile cleanup

def cleanup_tempfile(temp_dir: pathlib.Path | None) -> None:
    if temp_dir is None:
        return

    try:
        shutil.rmtree(temp_dir)
    except FileNotFoundError:
        pass

### Grand Orchestra Encrypt_file

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    base64_output: bool = False,
    scramble_name: bool = False
) -> pathlib.Path:

    zip_or_file_path, temp_dir = prepare_input_file(input_path)

    try:
        plaintext = load_plaintext(zip_or_file_path)

        plaintext = embed_filename_header(
            plaintext=plaintext,
            input_path=zip_or_file_path,
            add_header=scramble_name
        )

        salt, nonce = generate_salt_and_nonce()

        ciphertext = aes_encrypt(
            plaintext=plaintext,
            password=password,
            salt=salt,
            nonce=nonce
        )

        encrypted_blob = salt + nonce + ciphertext

        encrypted_blob = optional_base64_encode(
            data=encrypted_blob,
            base64_output=base64_output
        )

        final_output_path = determine_scramble(
            output_path=output_path,
            scramble_name=scramble_name
        )

        final_output_path.parent.mkdir(parents=True, exist_ok=True)

        atomic_output(
            output_path=final_output_path,
            data=encrypted_blob
        )

        return final_output_path

    finally:
        cleanup_tempfile(temp_dir)
