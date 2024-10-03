import random
import string
from encryptor import Encryptor

class PasswordGenerator:
    def __init__(self, length=16):
        self.length = length
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': string.punctuation
        }
        self.all_characters = ''.join(self.char_sets.values())

    def generate(self):
        password = [random.choice(char_set) for char_set in self.char_sets.values()]
        password.extend(random.choice(self.all_characters) for _ in range(self.length - len(self.char_sets)))
        random.shuffle(password)
        return ''.join(password)

class PasswordManager:
    def __init__(self):
        self.password_generator = PasswordGenerator()
        self.encryptor = Encryptor()

    def generate_passwords(self, accounts):
        passwords = {account: self.password_generator.generate() for account in accounts}
        result = "\n".join(f"{account}: {password}" for account, password in passwords.items())
        return result, passwords

    def encrypt_passwords(self, passwords_data, encryption_password):
        return self.encryptor.encrypt(passwords_data, encryption_password)

    def decrypt_passwords(self, encrypted_data, decryption_password):
        return self.encryptor.decrypt(encrypted_data, decryption_password)

    def get_change_password_link(self, account):
        links = {
            "facebook": "https://www.facebook.com/settings?tab=security&section=password",
            "instagram": "https://www.instagram.com/accounts/password/change/",
            "twitter": "https://twitter.com/settings/password",
            "linkedin": "https://www.linkedin.com/psettings/change-password",
            "snapchat": "https://accounts.snapchat.com/accounts/password_reset_options",
            "gmail": "https://myaccount.google.com/signinoptions/password",
            "outlook": "https://account.live.com/password/change",
            "hotmail": "https://account.live.com/password/change",
        }
        
        for key, link in links.items():
            if key in account.lower():
                return link
        
        return "No direct link available. Please log in to your account to change the password."