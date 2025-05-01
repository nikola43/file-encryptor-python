from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
import os
import hashlib

class Encryptor:
    def __init__(self):
        self.aes_key_size = 256 // 8  # 256 bits in bytes
        self.rsa_key_size = 2048      # RSA key size (stronger than 1024)
        self.rsa_public_key = None
        self.rsa_private_key = None

    def generate_rsa_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """Generate RSA key pair (2048 bits)"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size
        )

        # Extract public key
        public_key = private_key.public_key()

        # Save private key
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Store keys in memory for later use
        self.rsa_private_key = private_key
        self.rsa_public_key = public_key

        print(
            f"RSA keys generated - Private: {private_key_path}, Public: {public_key_path}")

    def load_rsa_keys_from_files(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """Load RSA keys from files"""
        # Load private key if it exists
        private_key = None
        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )

        # Load public key if it exists
        public_key = None
        if os.path.exists(public_key_path):
            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read()
                )

        # Store keys in memory for later use
        self.rsa_private_key = private_key
        self.rsa_public_key = public_key

    def load_rsa_keys_from_string(self, private_key, public_key):
        """Load RSA keys from PEM strings"""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None
        )

        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key.encode()
        )

        # Store keys in memory for later use
        self.rsa_private_key = private_key
        self.rsa_public_key = public_key

    def generate_aes_key(self):
        """Generate a random 256-bit AES key"""
        return os.urandom(self.aes_key_size)

    def calculate_md5(self, file_path):
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def encrypt_file(self, file_path):
        """
        Encrypt a file using hybrid encryption:
        1. Generate a random AES-256 key
        2. Encrypt the file with the AES key
        3. Encrypt the AES key with the RSA public key
        4. Store original file's MD5 hash for verification
        """
        # Calculate MD5 hash of the original file
        original_md5 = self.calculate_md5(file_path)
        print(f"Original file MD5: {original_md5}")

        # Load RSA public key
        public_key = self.rsa_public_key

        if not public_key:
            raise ValueError("Public key not found. Generate keys first.")

        # Generate a random AES key and IV
        aes_key = self.generate_aes_key()
        iv = os.urandom(16)  # 128-bit IV for AES

        # Read the file
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Encrypt the file with AES-256-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Add padding to make the plaintext a multiple of 16 bytes
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length]) * padding_length

        # Encrypt the file
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Encrypt the AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write the encrypted file
        encrypted_file_path = file_path + ".encrypted"
        with open(encrypted_file_path, "wb") as f:
            # Format: [RSA-encrypted AES key length (4 bytes)][RSA-encrypted AES key][IV][MD5 hash length (1 byte)][MD5 hash][Ciphertext]
            f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
            f.write(encrypted_key)
            f.write(iv)

            # Store the original MD5 hash
            md5_bytes = original_md5.encode('utf-8')
            f.write(len(md5_bytes).to_bytes(1, byteorder='big'))
            f.write(md5_bytes)

            f.write(ciphertext)

        print(f"File encrypted successfully: {encrypted_file_path}")
        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path):
        """
        Decrypt a file using hybrid encryption:
        1. Decrypt the AES key using the RSA private key
        2. Decrypt the file using the AES key
        3. Verify the MD5 hash to confirm successful decryption
        """
        # Load RSA private key
        private_key = self.rsa_private_key

        if not private_key:
            raise ValueError(
                "Private key not found. Cannot decrypt without private key.")

        # Read the encrypted file
        with open(encrypted_file_path, "rb") as f:
            # Read the length of the encrypted key
            key_length = int.from_bytes(f.read(4), byteorder='big')

            # Read the encrypted key
            encrypted_key = f.read(key_length)

            # Read the IV
            iv = f.read(16)

            # Read the original MD5 hash
            md5_length = int.from_bytes(f.read(1), byteorder='big')
            original_md5 = f.read(md5_length).decode('utf-8')

            # Read the ciphertext
            ciphertext = f.read()

        # Decrypt the AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the file with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        # Write the decrypted file
        decrypted_file_path = encrypted_file_path.replace(
            ".encrypted", ".decrypted")
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        # Calculate MD5 hash of the decrypted file
        decrypted_md5 = self.calculate_md5(decrypted_file_path)
        print(f"Original file MD5: {original_md5}")
        print(f"Decrypted file MD5: {decrypted_md5}")

        # Verify the MD5 hash
        if original_md5 == decrypted_md5:
            print("✅ MD5 verification successful - File integrity confirmed")
        else:
            print("❌ MD5 verification failed - File may be corrupted")

        print(f"File decrypted successfully: {decrypted_file_path}")
        return decrypted_file_path, original_md5 == decrypted_md5
