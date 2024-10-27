import getpass
import hashlib
from base64 import urlsafe_b64encode
import os
from cryptography.fernet import Fernet
import yaml

class PasswordManager:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.key = self.get_key()

        if not os.path.exists(self.file_path):
            self.initialize_file()

    def get_key(self) -> bytes:

        if os.path.exists(".key"):
            with open(".key", "rb") as file:
                key = file.read()
        
        else:
            key = getpass.getpass("Geben Sie bitte den Key für die Verschlüsselung ein: ")
            key = hashlib.sha256(key.encode()).digest()
            with open(".key", "wb") as file:
                file.write(key)
        return urlsafe_b64encode(key)
    
    def initialize_file(self) -> None:
        password = getpass.getpass("Erstellen Sie bitte ein Authentifizierungspasswort: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        encrypted_data = Fernet(self.key).encrypt(b"{}")

        with open(self.file_path, "w") as file: 
            data = {"auth_data": hashed_password, "passwords": encrypted_data}
            yaml.dump(data, file)

    
manager = PasswordManager("passwords.yaml")