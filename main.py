from encryptor import Encryptor

# Example usage
if __name__ == "__main__":
    encryptor = Encryptor()

    # First-time setup: Generate RSA keys
    encryptor.generate_rsa_keys()

    # Replace with your file path
    file_to_encrypt = "example.txt"

    # Encrypt the file (requires public key)
    encrypted_file = encryptor.encrypt_file(file_to_encrypt)

    # Decrypt the file (requires private key) and verify integrity
    decrypted_file, is_verified = encryptor.decrypt_file(encrypted_file)

    if is_verified:
        print(
            "File encryption and decryption completed successfully with integrity verified.")
    else:
        print("Warning: The decrypted file does not match the original file.")
