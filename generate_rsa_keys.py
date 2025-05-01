from encryptor import Encryptor

# Example usage
if __name__ == "__main__":
    encryptor = Encryptor()

    # First-time setup: Generate RSA keys
    encryptor.generate_rsa_keys()