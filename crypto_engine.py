"""CipherVault v2 streaming authenticated file format; CV01 backwards compatibility."""
import os
import struct
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from legacy_v1 import decrypt_file as decrypt_v1

MAGIC = b'CV02'
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = 4 + SALT_SIZE + NONCE_SIZE
CHUNK = 1024 * 1024

def key_from_password(password, salt):
    if not password:
        raise ValueError('Password cannot be empty')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))

def _paths(source, destination):
    src, dst = Path(source), Path(destination)
    if not src.is_file():
        raise ValueError('Source file does not exist')
    if src.resolve() == dst.resolve():
        raise ValueError('Source and destination must differ')
    if dst.exists():
        raise FileExistsError(f'Output already exists: {dst}')
    if not dst.parent.is_dir():
        raise ValueError('Output folder does not exist')
    return src, dst

def _temp(dst):
    fd, name = tempfile.mkstemp(prefix='.ciphervault-', dir=dst.parent)
    return fd, Path(name)

def _publish(temp, dst):
    # Atomic no-overwrite publication on the same filesystem.
    os.link(temp, dst)

def encrypt_file(source, destination, password, progress=None):
    src, dst = _paths(source, destination)
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    header = MAGIC + salt + nonce
    cipher = Cipher(algorithms.AES(key_from_password(password, salt)), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    fd, temp = _temp(dst)
    try:
        with os.fdopen(fd, 'wb') as out, src.open('rb') as inp:
            out.write(header)
            total = src.stat().st_size
            done = 0
            while data := inp.read(CHUNK):
                out.write(cipher.update(data))
                done += len(data)
                if progress: progress(done, total)
            out.write(cipher.finalize())
            out.write(cipher.tag)
            out.flush()
            os.fsync(out.fileno())
        _publish(temp, dst)
    finally:
        temp.unlink(missing_ok=True)

def decrypt_file(source, destination, password, progress=None):
    src, dst = _paths(source, destination)
    with src.open('rb') as inp:
        magic = inp.read(4)
    if magic == b'CV01':
        # Legacy format reads into memory; retained for v1 compatibility.
        return decrypt_v1(str(src), str(dst), password)
    size = src.stat().st_size
    if magic != MAGIC or size < HEADER_SIZE + TAG_SIZE:
        raise ValueError('Invalid or unsupported CipherVault file')
    with src.open('rb') as inp:
        header = inp.read(HEADER_SIZE)
        salt = header[4:20]
        nonce = header[20:32]
        inp.seek(-TAG_SIZE, os.SEEK_END)
        tag = inp.read(TAG_SIZE)
        inp.seek(HEADER_SIZE)
        decryptor = Cipher(algorithms.AES(key_from_password(password, salt)), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        remaining = size - HEADER_SIZE - TAG_SIZE
        fd, temp = _temp(dst)
        try:
            with os.fdopen(fd, 'wb') as out:
                total = remaining
                while remaining:
                    data = inp.read(min(CHUNK, remaining))
                    if not data:
                        raise ValueError('Encrypted file was truncated')
                    remaining -= len(data)
                    out.write(decryptor.update(data))
                    if progress: progress(total - remaining, total)
                try:
                    out.write(decryptor.finalize())
                except InvalidTag as exc:
                    raise ValueError('Wrong password or damaged encrypted file') from exc
                out.flush()
                os.fsync(out.fileno())
            _publish(temp, dst)
        finally:
            temp.unlink(missing_ok=True)
