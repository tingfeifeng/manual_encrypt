import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
import base64

class PublicKeyParseException(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class InvalidMessageException(Exception):
    """Custom exception for invalid or tampered messages."""
    def __init__(self, message="Decryption failed: Invalid or tampered message"):
        super().__init__(message)
        
class Generator():
    def __init__(self) -> None:
        self.derived_key = None
        pass
        
    def DH_keygen(self):
        self.private_key: X25519PrivateKey= x25519.X25519PrivateKey.generate()
        self.public_key: X25519PublicKey = self.private_key.public_key()
    
    def DH_key_exchange(self, other_pk: str):
        try: 
            received_public_key_bytes = base64.b64decode(other_pk)
            # Deserialize the bytes back into an X25519 public key
            received_public_key: X25519PublicKey = x25519.X25519PublicKey.from_public_bytes(received_public_key_bytes)
        except:
                # Raise custom exception if parsing fails
            raise PublicKeyParseException(f"Failed to parse public key")    
        shared_secret = self.private_key.exchange(received_public_key)
        self.derived_key = HKDF(
                        algorithm=SHA256(),
                        length=32,
                        salt=None,
                        info=b"handshake data",
                        backend=default_backend()
                    ).derive(shared_secret)
        # print(self.derived_key)
    
    def get_public_key(self) -> str:
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,  # Use Raw encoding for X25519
            format=serialization.PublicFormat.Raw
        )

        # Convert bytes to a base64-encoded string for transmission
        public_key_str = base64.b64encode(public_key_bytes).decode('utf-8')
        return public_key_str

    def encrypt_message(self, message: str):
        nonce = os.urandom(12)
        encryptor = Cipher(
                        algorithms.AES(self.derived_key),
                        modes.GCM(nonce),
                        backend=default_backend()
                    ).encryptor()
        ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
        auth_tag = encryptor.tag
        combined = nonce + ciphertext + auth_tag
        encoded_combined = base64.b64encode(combined).decode("utf-8")
        
        return encoded_combined
    
    def decrypt_message(self, encoded_combined: str):
        try:
            # Decode the base64-encoded string
            combined = base64.b64decode(encoded_combined)

            # Extract nonce, ciphertext, and auth_tag
            nonce = combined[:12]  # First 12 bytes are the nonce
            auth_tag = combined[-16:]  # Last 16 bytes are the tag (GCM tag is 16 bytes)
            ciphertext = combined[12:-16]  # Remainder is the ciphertext
            # print(nonce, auth_tag, ciphertext)
            # Decrypt the message
            decryptor = Cipher(
                algorithms.AES(self.derived_key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            ).decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode("utf-8")

        except Exception as e:
            # Raise custom exception if decryption fails
            raise InvalidMessageException() from e