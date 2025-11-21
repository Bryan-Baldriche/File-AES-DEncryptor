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
