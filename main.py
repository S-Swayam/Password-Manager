import os
import json
import bcrypt
import re
import stat
from cryptography.fernet import Fernet
import secrets
import string
import logging
from datetime import datetime, timedelta

# Constants for file paths
DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "passwords.json")
KEY_FILE = os.path.join(DATA_DIR, "key.key")
MASTER_HASH_FILE = os.path.join(DATA_DIR, "master_hash.txt")
LOG_FILE = os.path.join(DATA_DIR, "password_manager.log")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class PasswordManager:
    def __init__(self):
        """Initialize the PasswordManager and load the encryption key."""
        self.key = self._load_or_generate_key()

    def _load_or_generate_key(self):
        """Load the encryption key or generate a new one if it doesn't exist."""
        if not os.path.exists(KEY_FILE):
            self._generate_key()
        return self._load_key()

    def _load_key(self):
        """Load the encryption key from the key file."""
        try:
            with open(KEY_FILE, "rb") as key_file:
                return key_file.read()
        except Exception as e:
            logging.error(f"Error loading encryption key: {e}")
            return None

    def _generate_key(self):
        """Generate and save a new encryption key."""
        try:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            self._restrict_file_permissions(KEY_FILE)
            logging.info("New encryption key generated and saved.")
        except Exception as e:
            logging.error(f"Error generating encryption key: {e}")

    def _restrict_file_permissions(self, file_path):
        """Restrict file permissions to the owner only."""
        try:
            if os.name == "posix":  # Linux/macOS
                os.chmod(file_path, 0o600)
            elif os.name == "nt":  # Windows
                os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
        except Exception as e:
            logging.error(f"Error restricting file permissions: {e}")

    def _encrypt_message(self, message):
        """Encrypt a message using the stored key."""
        try:
            return Fernet(self.key).encrypt(message.encode()).decode()
        except Exception as e:
            logging.error(f"Error encrypting message: {e}")
            return None

    def _decrypt_message(self, encrypted_message):
        """Decrypt a message using the stored key."""
        try:
            return Fernet(self.key).decrypt(encrypted_message.encode()).decode()
        except Exception as e:
            logging.error(f"Error decrypting message: {e}")
            return None

    def _load_passwords(self):
        """Load passwords from the JSON file."""
        if not os.path.exists(DATA_FILE):
            return {}
        try:
            with open(DATA_FILE, "r") as file:
                return json.load(file) or {}
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logging.error(f"Error loading passwords: {e}")
            return {}

    def _save_passwords(self, passwords):
        """Save passwords to the JSON file."""
        try:
            with open(DATA_FILE, "w") as file:
                json.dump(passwords, file, indent=4)
            self._restrict_file_permissions(DATA_FILE)
            logging.info("Passwords saved successfully.")
        except Exception as e:
            logging.error(f"Error saving passwords: {e}")

    def _check_password_strength(self, password):
        """Check if a password meets strength requirements and provide detailed feedback."""
        feedback = []
        if len(password) < 8:
            feedback.append("At least 8 characters required.")
        if not re.search("[a-z]", password):
            feedback.append("At least one lowercase letter required.")
        if not re.search("[A-Z]", password):
            feedback.append("At least one uppercase letter required.")
        if not re.search("[0-9]", password):
            feedback.append("At least one number required.")
        if not re.search(r"[!@#$%^&*()_+=\-[\]{};:'\",.<>/?]", password):
            feedback.append("At least one special character required.")
        if password.lower() in ["password", "123456", "qwerty"]:
            feedback.append("Password is too common.")

        return "Strong: Good password!" if not feedback else "Weak: " + " ".join(feedback)

    def _generate_password(self, length=12):
        """Generate a strong, random password that meets all strength requirements."""
        while True:
            characters = string.ascii_letters + string.digits + string.punctuation
            password = "".join(secrets.choice(characters) for _ in range(length))
            if self._check_password_strength(password).startswith("Strong"):
                return password

    def _approve_password(self):
        """Ask the user if they like the generated password or want to generate another one."""
        while True:
            password = self._generate_password()
            print(f"Generated Password: {password}")
            choice = input("Do you like this password? (yes/no): ").strip().lower()
            if choice == "yes":
                return password
            elif choice == "no":
                print("Generating another password...")
            else:
                print("Invalid choice. Please enter 'yes' or 'no'.")

    def setup_or_validate_master_password(self):
        """Set up or validate the master password."""
        if not os.path.exists(MASTER_HASH_FILE):
            print("Setting up a new master password.")
            print("Warning: Password input will be visible.")
            while True:
                master_password = input("Enter a new master password: ")
                feedback = self._check_password_strength(master_password)
                if feedback.startswith("Strong"):
                    confirm = input("Confirm master password: ").strip()
                    if master_password == confirm:
                        break
                    print("Passwords do not match. Please try again.")
                print(f"Master password is weak. {feedback}")
            hashed_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
            try:
                with open(MASTER_HASH_FILE, "wb") as f:
                    f.write(hashed_password)
                self._restrict_file_permissions(MASTER_HASH_FILE)
                print("Master password set successfully!")
                return True
            except Exception as e:
                logging.error(f"Error setting master password: {e}")
                return False

        attempts = 3
        with open(MASTER_HASH_FILE, "rb") as f:
            stored_hash = f.read()

        while attempts > 0:
            print("Warning: Password input will be visible.")
            master_input = input("Enter master password: ")
            if bcrypt.checkpw(master_input.encode(), stored_hash):
                return True
            attempts -= 1
            print(f"Incorrect password. {attempts} attempts remaining.")

        print("Too many failed attempts. Exiting...")
        return False

    def add_password(self):
        """Add a new password entry."""
        passwords = self._load_passwords()

        account = self._get_input("Enter account name (e.g., Google, Facebook): ", "Account name cannot be empty.")
        if account in passwords:
            print(f"Warning: An account with the name '{account}' already exists.")
            return

        username = self._get_input("Enter username/email: ", "Username cannot be empty.")
        password = self._get_password_input()

        encrypted_password = self._encrypt_message(password)
        if encrypted_password:
            passwords[account] = {
                "username": username,
                "password": encrypted_password,
                "expiry": (datetime.now() + timedelta(days=90)).isoformat()
            }
            self._save_passwords(passwords)
            print(f"Password for '{account}' added successfully!")

    def update_password(self):
        """Update an existing password entry."""
        passwords = self._load_passwords()
        if not passwords:
            print("No accounts found. Please add an account first.")
            return

        account = self._get_input("Enter account name to update: ", "Account name cannot be empty.")
        if account not in passwords:
            print(f"Account '{account}' not found.")
            return

        username = self._get_input("Enter new username/email (or press Enter to keep current): ", optional=True)
        password = self._get_password_input()

        encrypted_password = self._encrypt_message(password)
        if encrypted_password:
            if username:
                passwords[account]["username"] = username
            passwords[account]["password"] = encrypted_password
            passwords[account]["expiry"] = (datetime.now() + timedelta(days=90)).isoformat()
            self._save_passwords(passwords)
            print(f"Password for '{account}' updated successfully!")

    def delete_password(self):
        """Delete a password entry."""
        passwords = self._load_passwords()
        if not passwords:
            print("No accounts found. Please add an account first.")
            return

        account = self._get_input("Enter account name to delete: ", "Account name cannot be empty.")
        if account not in passwords:
            print(f"Account '{account}' not found.")
            return

        confirm = input(f"Are you sure you want to delete the password for '{account}'? (yes/no): ").strip().lower()
        if confirm == "yes":
            del passwords[account]
            self._save_passwords(passwords)
            print(f"Password for '{account}' deleted successfully!")
        else:
            print("Deletion canceled.")

    def list_accounts(self):
        """List all accounts stored in the password manager."""
        passwords = self._load_passwords()
        if not passwords:
            print("No accounts found. Please add an account first.")
            return

        print("\nList of Accounts:")
        for account, data in passwords.items():
            username = data.get("username", "No username set")
            print(f"- Account: {account}")
            print(f"  Username: {username}")
        print()

    def export_passwords(self):
        """Export passwords to a file with a custom name provided by the user."""
        passwords = self._load_passwords()
        if not passwords:
            print("No passwords found to export.")
            return

        file_name = self._get_input("Enter a name for the export file (e.g., my_passwords.json): ", "File name cannot be empty.")
        if not file_name.endswith(".json"):
            file_name += ".json"

        export_file_path = os.path.join(DATA_DIR, file_name)

        if os.path.exists(export_file_path):
            confirm = input(f"File '{export_file_path}' already exists. Overwrite? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("Export canceled.")
                return

        export_type = self._get_input("Do you want an encrypted file or a plain-text file? (encrypted/plain): ", valid_options=["encrypted", "plain"])

        if export_type == "plain":
            if not self._validate_master_password():
                print("Incorrect master password. Export canceled.")
                return

            decrypted_passwords = {}
            for account, data in passwords.items():
                decrypted_password = self._decrypt_message(data["password"])
                decrypted_passwords[account] = {
                    "username": data["username"],
                    "password": decrypted_password,
                    "expiry": data["expiry"]
                }
            passwords_to_export = decrypted_passwords
        else:
            passwords_to_export = passwords

        try:
            with open(export_file_path, "w") as file:
                json.dump(passwords_to_export, file, indent=4)
            print(f"Passwords exported successfully to '{export_file_path}'.")
        except Exception as e:
            logging.error(f"Error exporting passwords: {e}")
            print("Failed to export passwords. Please check the logs for details.")

    def _get_input(self, prompt, error_message="Invalid input.", optional=False, valid_options=None):
        """Helper method to get user input with validation."""
        while True:
            user_input = input(prompt).strip()
            if optional and not user_input:
                return user_input
            if user_input:
                if valid_options and user_input.lower() not in valid_options:
                    print(f"Invalid choice. Please enter one of: {', '.join(valid_options)}")
                else:
                    return user_input
            print(error_message)

    def _get_password_input(self):
        """Helper method to get a password from the user."""
        while True:
            password = input("Enter password (or type 'generate' to create a strong one): ").strip()
            if password.lower() == "generate":
                return self._approve_password()
            elif password:
                feedback = self._check_password_strength(password)
                print(feedback)
                if "Weak" not in feedback:
                    return password
                print("Please try again.")
            else:
                print("Password cannot be empty. Please try again.")

    def _validate_master_password(self):
        """Validate the master password for sensitive operations."""
        with open(MASTER_HASH_FILE, "rb") as f:
            stored_hash = f.read()
        master_input = input("Enter master password to proceed: ").strip()
        return bcrypt.checkpw(master_input.encode(), stored_hash)

def main():
    """Main function to run the password manager."""
    print("Welcome to the Password Manager!")

    manager = PasswordManager()

    if not manager.setup_or_validate_master_password():
        return

    while True:
        print("\n1. Add Password\n2. Update Password\n3. Delete Password\n4. List Accounts\n5. Export Passwords\n6. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            manager.add_password()
        elif choice == "2":
            manager.update_password()
        elif choice == "3":
            manager.delete_password()
        elif choice == "4":
            manager.list_accounts()
        elif choice == "5":
            manager.export_passwords()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
