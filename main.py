import getpass
import hashlib
from base64 import urlsafe_b64encode
import os
from cryptography.fernet import Fernet
import yaml
from typing import Dict, Optional

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
    
    def authenticate(self) -> bool:
        password = getpass.getpass("Geben Sie bitte das Masterpasswort ein: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        with open(self.file_path, "r") as file:
            data = yaml.safe_load(file)
            return data["auth_data"] == hashed_password

    def load_passwords(self) -> Dict[str, str]:
        with open(self.file_path, "r") as file:
            data = yaml.safe_load(file)
            encrypted_data = data["passwords"]

        decrypted_data = Fernet(self.key).decrypt(encrypted_data)
        return yaml.safe_load(decrypted_data)
    
    def save_passwords(self, passwords: Dict[str, str]) -> None:
        encrypted_data = Fernet (self.key).encrypt(yaml.dump(passwords).encode())

        with open(self.file_path, "r") as file:
            data = yaml.safe_load(file)
        
        data["passwords"] = encrypted_data

        with open(self.file_path, "w") as file:
            yaml.dump(data, file)

    def add_password(self, identifier: str, password: str) -> None:
        if not self.authenticate():
            print("Authentifizierung fehlgeschlagen")
            return
        
        passwords = self.load_passwords()
        passwords[identifier] = password

        self.save_passwords(passwords)
        print(f"Passwort für {identifier} erolgreich hinzugefügt!")
        
    def get_password(self, identifier: str) -> Optional[str]:
        if not self.authenticate():
            print("Authentifizierung fehlgeschlagen")
            return
        
        passwords = self.load_passwords()
        if identifier in passwords:
            password = passwords[identifier]
            return print(f"Das Passwort lautet {password}")
        print(f"Kein Passwort für {identifier} gefunden")
        return None


def main_menu():
    manager = PasswordManager("passwords.yaml")
    
    while True:
        print("\nPasswortmanager Menü")
        print("1. Passwort hinzufügen")
        print("2. Passwort abrufen")
        print("3. Beenden")
        
        choice = input("Bitte wählen Sie eine Option (1-3): ")

        if choice == "1":
            identifier = input("Geben Sie die Kennung (z.B. Website oder Dienst) ein: ")
            password = getpass.getpass("Geben Sie das Passwort ein: ")
            manager.add_password(identifier, password)

        elif choice == "2":
            identifier = input("Geben Sie die Kennung (z.B. Website oder Dienst) ein: ")
            manager.get_password(identifier)

        elif choice == "3":
            print("Beende das Programm...")
            break

        else:
            print("Ungültige Auswahl, bitte erneut versuchen.")

if __name__ == "__main__":
    main_menu()
