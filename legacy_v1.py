"""CipherVault file format v1: magic(4), salt(16), nonce(12), ciphertext+tag."""
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

MAGIC = b'CV01'
SALT_SIZE = 16
NONCE_SIZE = 12

def _key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError('Password cannot be empty')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))

def encrypt_file(source: str, destination: str, password: str) -> None:
    src, dst = Path(source), Path(destination)
    if src.resolve() == dst.resolve():
        raise ValueError('Source and destination must differ')
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    header = MAGIC + salt + nonce
    encrypted = AESGCM(_key(password, salt)).encrypt(nonce, src.read_bytes(), header)
    with dst.open('xb') as output:
        output.write(header + encrypted)

def decrypt_file(source: str, destination: str, password: str) -> None:
    src, dst = Path(source), Path(destination)
    if src.resolve() == dst.resolve():
        raise ValueError('Source and destination must differ')
    data = src.read_bytes()
    if len(data) < 4 + SALT_SIZE + NONCE_SIZE + 16 or data[:4] != MAGIC:
        raise ValueError('Invalid or unsupported CipherVault file')
    salt = data[4:20]
    nonce = data[20:32]
    try:
        plaintext = AESGCM(_key(password, salt)).decrypt(nonce, data[32:], data[:32])
    except InvalidTag as exc:
        raise ValueError('Wrong password or damaged encrypted file') from exc
    with dst.open('xb') as output:
        output.write(plaintext)
