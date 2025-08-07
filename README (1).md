 CipherVault – Universal Data Encryption Framework

CipherVault is a flexible, secure, and developer-friendly encryption framework designed to protect your most sensitive data — from personal documents to enterprise assets — using robust cryptographic standards and a streamlined CLI interface.

Purpose
CipherVault helps individuals, developers, and organizations encrypt files, folders, or even entire datasets easily — with full control over algorithms, encryption modes, and stealth protection. No GUI clutter. No cloud dependencies. Just pure encryption, on your terms.

---

 Key Features
Multi-layer encryption support
  AES-256, Fernet, XOR – choose your preferred algorithm per use case.

Folder & file-level encryption 
  Encrypt entire directories or single files with ease.

Stealth Mode
  Disguise encrypted files as innocent-looking images (JPG containers).

-Backup & recovery system 
  Automatic backup before encryption and auto-cleanup after decryption.

- Smart auto-discovery 
  Just provide the filename – CipherVault searches intelligently across common folders (Desktop, Downloads, Documents…).

Strong key derivation & hashing
  PBKDF2-HMAC (100K iterations) + SHA-512 + Nonce for maximum resistance.

- Modular code structure 
  Easy to extend and integrate in your own Python-based security tools.

---

Quick Start

 1. Clone the repository
```bash
git clone https://github.com/yourusername/CipherVault.git
cd CipherVault
```

 2. Install dependencies
```bash
pip install -r requirements.txt
```

 3. Run basic encryption
```bash
python ciphervault_inplace.py --encrypt --file "example.pdf" --password "StrongKey123"
```

---

🧩 Use Case Examples

Encrypt a folder:
```bash
python ciphervault_inplace.py --encrypt --folder "Projects" --password "MyFolderKey"
```

Enable stealth mode:
bash
python ciphervault_inplace.py --encrypt --file "secret.docx" --password "Stealthy!" --stealth


 Decrypt a file:
bash
python ciphervault_inplace.py --decrypt --file "example.pdf.cvault" --password "StrongKey123"


---

Supported Algorithms

| Algorithm  | Strength        | Recommended Use        |
|------------|------------------|--------------------------|
| AES-256    | 🔒🔒🔒🔒🔒   | General file/folder encryption |
| Fernet     | 🔒🔒🔒🔒     | Text and config encryption     |
| XOR        | 🔓             | Obfuscation or speed-based use (not secure alone) |

---

Project Structure

```
CipherVault/
│
├── ciphervault_inplace.py     # Main engine (in-place encryption)
├── ciphervault_enhanced.py    # Variant with cloned encryption
├── simple_test.py             # Quick test script
├── utils/                     # Encryption helpers and utilities
└── examples/                  # Sample files and templates
```

---

Documentation

- Full CLI command reference and advanced examples are available in the [Wiki](https://github.com/yourusername/CipherVault/wiki).
- For API integration or module-based use, check `utils/` and function docstrings.

---

🧪 Security Notes

- All encryption is local. No remote storage or telemetry.
- Keys and passwords are never stored.
- Encrypted files are undecryptable without the correct password*.
- No backdoors, no hidden keys. What you encrypt is yours alone.

---

Contributions

We welcome clean pull requests, bug reports, and feature suggestions. Please open an [Issue](https://github.com/yourusername/CipherVault/issues) or create a [Discussion](https://github.com/yourusername/CipherVault/discussions) for proposals.

---

 License

Licensed under the **MIT License** — free to use, modify, and distribute with attribution.

---

Behind the Vault

CipherVault was built with security-first design principles. It's ideal for:
- Developers who want full control over encryption.
- Individuals who need strong protection without bloated GUIs.
- Activists, journalists, and professionals working with sensitive data.

---

Ready to encrypt like a pro?

```bash
git clone https://github.com/yourusername/CipherVault.git
cd CipherVault
pip install -r requirements.txt
```


