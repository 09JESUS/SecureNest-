import os
import json
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = 'vault.enc'
SALT_FILE = 'salt.salt'

# Generate a new salt if it doesn't exist
def generate_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'wb') as f:
            f.write(os.urandom(16))

# Derive a key from the master password
def derive_key(password: str) -> bytes:
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt and save vault
def save_vault(vault, fernet):
    encrypted = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted)

# Load and decrypt vault
def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, 'rb') as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted)
    return json.loads(decrypted.decode())

# Main app
def main():
    print("🔒 Welcome to SecureNest 🐣🔒")
    generate_salt()
    master_password = getpass.getpass("Enter master password: ")

    key = derive_key(master_password)
    fernet = Fernet(key)

    try:
        vault = load_vault(fernet)
    except Exception:
        print("❌ Invalid master password or corrupted vault!")
        return

    while True:
        print("\nOptions:")
        print("1. Add a new password")
        print("2. View saved passwords")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ").strip()

        if choice == '1':
            site = input("Enter site name: ").strip()
            username = input("Enter username/email: ").strip()
            password = getpass.getpass("Enter password: ").strip()
            vault[site] = {'username': username, 'password': password}
            save_vault(vault, fernet)
            print("✅ Password saved securely!")

        elif choice == '2':
            for site, creds in vault.items():
                print(f"\n🔹 Site: {site}")
                print(f"   Username: {creds['username']}")
                print(f"   Password: {creds['password']}")

        elif choice == '3':
            print("\nGoodbye! 👋")
            print("Created with ❤️ by Fsolution.-Dev")
            break
        else:
            print("Invalid option. Try again!")

if __name__ == "__main__":
    main()
