import getpass
import hashlib
from base64 import urlsafe_b64decode
import os

class PasswordManager:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.key = self.get_key()

    def get_key(self) -> bytes:

        if os.path.exists(".key"):
            with open(".key", "rb") as file:
                key = file.read()
        
        else:
            key = getpass.getpass("Geben Sie bitte den Key für die Verschlüsselung ein: ")
            key = hashlib.sha256(key.encode()).digest()
            with open(".key", "wb") as file:
                file.write(key)
        return urlsafe_b64decode(key)
    
manager = PasswordManager("file.yaml")