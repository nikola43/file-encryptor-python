# 🔐 Secure File Encryption Tool

A robust Python tool for secure file encryption using hybrid RSA/AES encryption.

## ✨ Features

- 🛡️ **Hybrid Encryption**: Combines RSA (2048-bit) and AES (256-bit) for maximum security
- 🔑 **Key Management**: Generate, save, and load RSA key pairs
- 📝 **File Integrity**: MD5 hash verification ensures file integrity
- 🔄 **File Operations**: Easily encrypt and decrypt files

## 🚀 Getting Started

### Prerequisites

```bash
pip install cryptography
```

### Basic Usage

```python
from encryptor import Encryptor

# Create an encryptor instance
encryptor = Encryptor()

# Generate RSA keys (only needed once)
encryptor.generate_rsa_keys()

# Encrypt a file
encrypted_file = encryptor.encrypt_file("secret_document.txt")

# Decrypt a file
decrypted_file, is_verified = encryptor.decrypt_file("secret_document.txt.encrypted")
```

## 🔧 How It Works

1. 🔐 **Encryption Process**:
   - Generates a random AES-256 key for file encryption
   - Encrypts the file data using AES in CBC mode
   - Encrypts the AES key using the RSA public key
   - Stores the encrypted key, IV, original file hash, and encrypted data

2. 🔓 **Decryption Process**:
   - Decrypts the AES key using the RSA private key
   - Uses the AES key to decrypt the file data
   - Verifies the file integrity using the stored MD5 hash

## 🛠️ Advanced Usage

### Loading Keys from Files

```python
# Load previously generated keys
encryptor = Encryptor()
encryptor.load_rsa_keys_from_files("private_key.pem", "public_key.pem")
```

### Loading Keys from Strings

```python
# Load keys from PEM format strings
encryptor = Encryptor()
encryptor.load_rsa_keys_from_string(private_key_pem, public_key_pem)
```

## ⚠️ Security Notes

- Keep your private key secure and never share it
- For maximum security, consider password-protecting the private key
- The RSA key size (2048 bits) provides strong security but can be increased if needed

## 📋 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 📬 Contact

Created by nikola43