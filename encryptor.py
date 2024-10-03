import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Encryptor:
    def __init__(self, salt_length=16):
        self.salt_length = salt_length

    def _generate_salt(self):
        return os.urandom(self.salt_length)

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, data, password):
        salt = self._generate_salt()
        key = self._derive_key(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return salt + encrypted_data

    def decrypt(self, encrypted_data, password):
        salt, data = encrypted_data[:self.salt_length], encrypted_data[self.salt_length:]
        key = self._derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(data).decode()
