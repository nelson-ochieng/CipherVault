# CipherVault v2 🔐

Offline, open-source desktop encryption application for Windows (also runnable on Linux/macOS).

## Features
- AES-256-GCM authenticated encryption and Scrypt password-based key derivation
- Streaming file processing (1 MiB chunks) for large files
- Batch file processing and drag-and-drop interface
- Folder encryption: folders are zipped into an encrypted `.cvlt` file; after decryption, the resulting ZIP can be extracted using your operating system
- Decrypts `.cvlt` files created by CipherVault v1 (CV01)
- Atomic, no-overwrite output publishing; originals remain untouched
- No cloud services, analytics, or paid APIs

## Windows 11 quick start

Open this folder in VS Code, then run in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Drag files or folders into the list, enter a strong password, click Encrypt, and choose an output directory. To decrypt, select `.cvlt` files and click Decrypt.

## Build a standalone Windows executable

Run `build_windows.bat` on **Windows**. The generated executable is `dist\CipherVault.exe`. Windows SmartScreen may warn about unsigned executables. This is not a signed installer; no code signing is included.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Security design and limitations

- CV02 file layout: `CV02` (4 bytes) + random salt (16 bytes) + random nonce (12 bytes) + ciphertext (streamed) + GCM tag (16 bytes).
- Scrypt parameters: N=32768, r=8, p=1; 32-byte AES key.
- The full header is authenticated as GCM additional authenticated data.
- Wrong passwords, corruption and tampering fail without publishing decrypted output. Temporary files are removed, though securely erasing their filesystem traces is **not** guaranteed.
- CV01 backward compatibility loads legacy files into memory. New CV02 files stream data.
- Folder encryption first creates a temporary ZIP archive **in the system temporary directory**. This archive contains unencrypted folder data until it is removed. Do not use folder mode for highly sensitive data on untrusted disks. A future release should stream the archive directly into encryption.
- ZIP archives are not automatically extracted, avoiding unsafe automatic extraction of archive paths.
- Input filenames remain visible in the source directory and output encrypted filenames are derived from source names. File sizes are observable. ZIP entries are encrypted inside the vault.
- Strong unique passwords are essential; there is no password recovery.
- Do not edit encrypted files while operations are running; concurrent modification is unsupported.
- This is an educational open-source project, **not independently security audited**. Keep backups and test decryption before relying on it.

## GitHub

Publish source code, tests and documentation. Never commit private documents, passwords, or encrypted files containing real secrets.

## License

MIT (see LICENSE).
