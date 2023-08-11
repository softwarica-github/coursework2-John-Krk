import hashlib
import binascii
import os
import json
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import simpledialog
from PIL import ImageTk, Image
import pyotp
from datetime import datetime
import sqlite3
from hdwallet import HDWallet
from web3 import Web3
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import random

# Create the SQLite databases and tables if they don't exist yet
conn = sqlite3.connect("user_database.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (number TEXT PRIMARY KEY, name TEXT, address TEXT, address_Eth)")
cursor.execute("CREATE TABLE IF NOT EXISTS passwords (number TEXT PRIMARY KEY, password TEXT)")
conn.commit()
conn.close()

conn = sqlite3.connect("admin_database.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS logged_users (number TEXT PRIMARY KEY, timestamp TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS admin (id TEXT PRIMARY KEY, password TEXT)")
cursor.execute("INSERT OR IGNORE INTO admin VALUES (?, ?)", ("admin", "root"))
conn.commit()
conn.close()

class HDWallet:
    def __init__(self):
        self.private_key = None

    def generate_ethereum_private_key(self):
        # Generate a random 32-byte private key (for demonstration purposes only)
        private_key = os.urandom(32)
        return private_key

class User:

    def get_balance(self):
        return self.wallet.get_balance()
    
    def __init__(self, number, name, address, web3):
        self.number = number
        self.name = name
        self.address = address
        self.web3 = web3
        self.balance = 1000.0  # Set initial balance to 1000 units
        self.wallet = Wallet(self.web3)

        def get_balance(self):
            return self.wallet.get_balance()

    def encrypt_private_key(self, passphrase):
        # Encrypt the private key and store the encrypted value and salt
        self.encrypted_private_key, self.salt = self.wallet.encrypt_private_key(passphrase)

    def decrypt_private_key(self, passphrase):
        # Decrypt the private key using the passphrase and salt and update the wallet
        decrypted_private_key = self.wallet.decrypt_private_key(self.encrypted_private_key, passphrase, self.salt)
        if decrypted_private_key:
            self.wallet.hdwallet.private_key = decrypted_private_key

    def recover_wallet(self, passphrase, encrypted_private_key, salt):
        # Attempt to decrypt the private key using the passphrase and salt
        decrypted_private_key = self.wallet.decrypt_private_key(encrypted_private_key, passphrase, salt)
        if decrypted_private_key:
            # Update the wallet's private key with the decrypted key
            self.wallet.hdwallet.private_key = decrypted_private_key

            # Update the user's encrypted_private_key and salt attributes
            self.encrypted_private_key = encrypted_private_key
            self.salt = salt

            # Show a success message
            messagebox.showinfo("Wallet Recovery", "Wallet recovered successfully")
        else:
            # Show an error message if the recovery fails
            messagebox.showerror("Wallet Recovery", "Wallet recovery failed. Incorrect passphrase or encrypted private key.")

class TransactionStatement:
    def __init__(self, timestamp, recipient, amount):
        self.timestamp = timestamp
        self.recipient = recipient
        self.amount = amount

    def get_details(self):
        formatted_timestamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"Timestamp: {formatted_timestamp}, Recipient: {self.recipient}, Amount: {self.amount}"


class Wallet:

    def __init__(self, web3):
        self.hdwallet = HDWallet()
        self.statements = []
        self.web3 = web3
        self.balance = 10000  #
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()

        self.hdwallet.private_key = self.hdwallet.generate_ethereum_private_key()

    def generate_private_key(self):
        private_key = os.urandom(32)
        return binascii.hexlify(private_key).decode()

    def generate_public_key(self):
        private_key_bytes = binascii.unhexlify(self.private_key)
        public_key = hashlib.sha256(private_key_bytes).hexdigest()
        return public_key

    
    def get_wallet_address(self):
        # Alchemy API endpoint URL
        alchemy_api_url = "https://eth-sepolia.g.alchemy.com/v2/qO3S3AP_0AMXRA57sKFbA0hIlLi_cNzS"

        # Replace "ALCHEMY_API_KEY" with your actual Alchemy API key
        alchemy_api_key = "qO3S3AP_0AMXRA57sKFbA0hIlLi_cNzS"

        # Set headers for the API request
        headers = {"Authorization": f"Bearer {alchemy_api_key}"}

        # Make a GET request to the Alchemy API
        response = requests.get(alchemy_api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if "result" in data:
                return data["result"]
            else:
                return "Error: Wallet address not found in API response"
        else:
            return "Error: Failed to fetch wallet address from the Alchemy API"


    def get_balance(self):
        return self.balance


    def send_transaction(self, recipient, amount):
        if amount <= 0:
            messagebox.showerror("Error", "Transaction amount must be greater than 0")
            return

        # Check if the user has sufficient balance
        if self.balance < amount:
            messagebox.showerror("Error", "Insufficient balance to send the transaction")
            return
        
        # Simulate the transaction by deducting the amount from the balance
        self.balance -= amount
        
        messagebox.showinfo("Transaction Sent", f"Sending {amount} coins to {recipient}")
        self.add_transaction_statement(recipient, amount)

    def recharge_statement(self, amount):
        if amount <= 0:
            messagebox.showerror("Error", "Recharge amount must be greater than 0")
            return
        # Recharge the statement by adding the amount to the balance
        self.balance += amount

        messagebox.showinfo("Statement Recharged", f"Statement recharged with {amount} coins")
        self.add_transaction_statement("Statement Recharge", amount)

    def pay_bill(self, bill_type, bill_amount):
        if bill_amount <= 0:
            messagebox.showerror("Error", "Bill amount must be greater than 0")
            return

        # Check if the user has sufficient balance to pay the bill
        if self.balance < bill_amount:
            messagebox.showerror("Error", "Insufficient balance to pay the bill")
            return

        # Simulate paying the bill by deducting the amount from the balance
        self.balance -= bill_amount

        messagebox.showinfo("Bill Payment", f"Paying {bill_amount} coins for {bill_type} bill")
        self.add_transaction_statement(bill_type, bill_amount)

    def encrypt_private_key(self, passphrase):
         # Generate a random salt
         salt = os.urandom(16)

         # Derive the encryption key from the passphrase and salt
         kdf = PBKDF2HMAC(
             algorithm=hashes.SHA256(),
             length=32,
             salt=salt,
             iterations=100000,
         )
         key = kdf.derive(passphrase.encode())

         # Create a Fernet instance with the derived key
         fernet = Fernet(base64.urlsafe_b64encode(key))

         # Convert the private key to bytes
         private_key_bytes = self.hdwallet.private_key

         # Encrypt the private key
         encrypted_private_key = fernet.encrypt(private_key_bytes)

        # Save the encrypted private key, key (in base64), and the salt to a file
         with open("encrypted_private_key.txt", "wb") as file:
            file.write(encrypted_private_key + b'\n')
            file.write(base64.urlsafe_b64encode(key) + b'\n')
            file.write(salt)

        # Return the encrypted private key, key (in base64), and the salt
         return encrypted_private_key, base64.urlsafe_b64encode(key), salt
    

    def decrypt_private_key(self, encrypted_private_key, passphrase, salt):
        try:
            # Derive the encryption key from the passphrase and salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(passphrase.encode())

            # Create a Fernet instance with the derived key
            fernet = Fernet(base64.urlsafe_b64encode(key))

            # Decrypt the private key
            decrypted_private_key_bytes = fernet.decrypt(encrypted_private_key)

            # Convert the decrypted bytes back to a string
            decrypted_private_key = decrypted_private_key_bytes.decode()

            # Update the wallet's private key with the decrypted key
            self.hdwallet.private_key = decrypted_private_key

            return decrypted_private_key
        except Exception as e:
            print("Decryption error:", str(e))
            return None

    def generate_otp():
        # Generate a random six-digit OTP
        return ''.join(str(random.randint(0, 9)) for _ in range(6))

    def confirm_transaction(self, recipient, amount):
        # Generate a transaction confirmation prompt
        otp = self.generate_otp()
        messagebox.showinfo("Transaction Confirmation", f"Confirm transaction to {recipient} for {amount} coins. OTP: {otp}")
        self.add_transaction_statement(recipient, amount)

    def secure_backup(self):
        # Check if the encrypted_private_key and salt attributes are set
        if not self.encrypted_private_key or not self.salt:
            messagebox.showerror("Error", "Wallet private key is not encrypted. Perform private key encryption first.")
            return

        # Prompt the user for a secure backup passphrase (not the same as the wallet passphrase)
        passphrase = simpledialog.askstring("Secure Backup", "Enter a secure backup passphrase:", show="*")
        confirm_passphrase = simpledialog.askstring("Secure Backup", "Confirm secure backup passphrase:", show="*")

        # Check if the passphrase and its confirmation match
        if passphrase != confirm_passphrase:
            messagebox.showerror("Error", "Passphrases do not match. Backup failed.")
            return

        # Generate a dictionary to store the backup data
        backup_data = {
            "encrypted_private_key": self.encrypted_private_key.decode(),  # Convert bytes to string
            "salt": base64.urlsafe_b64encode(self.salt).decode(),  # Convert bytes to string
        }

        # Convert the dictionary to JSON format
        backup_json = json.dumps(backup_data)

        # Encrypt the JSON data using Fernet with the secure backup passphrase
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=100000,
            )
            key = kdf.derive(passphrase.encode())
            fernet = Fernet(base64.urlsafe_b64encode(key))
            encrypted_backup = fernet.encrypt(backup_json.encode())
        except Exception as e:
            messagebox.showerror("Error", "Error encrypting backup data.")
            return

        # Save the encrypted backup to a file
        try:
            with open("secure_backup.dat", "wb") as file:
                file.write(encrypted_backup)
        except Exception as e:
            messagebox.showerror("Error", "Error saving the secure backup file.")
            return

        # Show a success message
        messagebox.showinfo("Secure Backup", "Secure backup created successfully. Save the 'secure_backup.dat' file in a safe place.")
    
    def recover_wallet(self, passphrase, encrypted_private_key, salt):
        # Implement logic for wallet recovery using passphrase and encrypted private key
        decrypted_private_key = self.decrypt_private_key(encrypted_private_key, passphrase, salt)
        if decrypted_private_key:
            self.hdwallet.private_key = decrypted_private_key
            messagebox.showinfo("Wallet Recovery", "Wallet recovered successfully")
        else:
            messagebox.showerror("Error", "Failed to recover the wallet. Invalid passphrase or encrypted private key.")

    def add_transaction_statement(self, recipient, amount):
        timestamp = datetime.now()
        statement = TransactionStatement(timestamp, recipient, amount)
        self.statements.append(statement)

class WalletDashboard:
    def __init__(self, root, user):
        self.root = root
        self.root.title("Cryptocurrency Wallet - Dashboard")
        self.user = user

        self.show_dashboard()

    def show_dashboard(self):
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.configure(style="Custom.TFrame")
        self.frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.welcome_label = ttk.Label(self.frame, text=f"Welcome, {self.user.name}!")
        self.welcome_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        self.balance_label = ttk.Label(self.frame, text="Balance:")
        self.balance_label.grid(row=1, column=0, padx=10, pady=5)

        self.balance_value = ttk.Label(self.frame, text=self.get_balance())
        self.balance_value.grid(row=1, column=1, padx=10, pady=5)

        self.send_button = ttk.Button(self.frame, text="Send", command=self.show_send_dialog)
        self.send_button.grid(row=2, column=0, padx=10, pady=5)

        self.recharge_button = ttk.Button(self.frame, text="Recharge", command=self.show_recharge_dialog)
        self.recharge_button.grid(row=2, column=1, padx=10, pady=5)

        self.pay_bill_button = ttk.Button(self.frame, text="Pay Bill", command=self.show_pay_bill_dialog)
        self.pay_bill_button.grid(row=3, column=0, padx=10, pady=5)

        self.encrypt_button = ttk.Button(self.frame, text="Encrypt Private Key", command=self.show_encrypt_dialog)
        self.encrypt_button.grid(row=3, column=1, padx=10, pady=5)

        self.decrypt_button = ttk.Button(self.frame, text="Decrypt Private Key", command=self.show_decrypt_dialog)
        self.decrypt_button.grid(row=4, column=0, padx=10, pady=5)

        self.backup_button = ttk.Button(self.frame, text="Backup Wallet", command=self.backup_wallet)
        self.backup_button.grid(row=4, column=1, padx=10, pady=5)

        self.statement_button = ttk.Button(self.frame, text="View Statements", command=self.show_statements)
        self.statement_button.grid(row=6, column=0, padx=10, pady=5)


        self.logout_button = ttk.Button(self.frame, text="Logout", command=self.logout)
        self.logout_button.grid(row=5, column=0, padx=10, pady=5)

    def get_balance(self):
        return self.user.get_balance()

    def show_send_dialog(self):
        recipient = simpledialog.askstring("Send", "Enter recipient:")
        amount = simpledialog.askfloat("Send", "Enter amount:")
        if recipient and amount:
            self.user.wallet.send_transaction(recipient, amount)

    def show_recharge_dialog(self):
        amount = simpledialog.askfloat("Recharge", "Enter amount:")
        if amount:
            self.user.wallet.recharge_statement(amount)

    def show_pay_bill_dialog(self):
        bill_type = simpledialog.askstring("Pay Bill", "Enter bill type:")
        bill_amount = simpledialog.askfloat("Pay Bill", "Enter bill amount:")
        if bill_type and bill_amount:
            self.user.wallet.pay_bill(bill_type, bill_amount)

    def show_encrypt_dialog(self):
        passphrase = simpledialog.askstring("Encrypt Private Key", "Enter passphrase:")
        if passphrase:
            encrypted_private_key = self.user.wallet.encrypt_private_key(passphrase)
            messagebox.showinfo("Private Key Encryption", f"Private key encrypted with passphrase:\n{encrypted_private_key}")

    def show_decrypt_dialog(self):
        encrypted_private_key = simpledialog.askstring("Decrypt Private Key", "Enter encrypted private key:")
        passphrase = simpledialog.askstring("Decrypt Private Key", "Enter passphrase:")
        if encrypted_private_key and passphrase:
            decrypted_private_key = self.user.wallet.decrypt_private_key(encrypted_private_key, passphrase)
            if decrypted_private_key:
                messagebox.showinfo("Private Key Decryption", f"Decrypted private key:\n{decrypted_private_key}")

    def backup_wallet(self):
        self.user.wallet.secure_backup()
        messagebox.showinfo("Backup", "Secure backup created")

    def show_statements(self):
        statements = self.user.wallet.statements
        if statements:
           statement_strings = [f"{statement.timestamp}: {statement.get_details()}" for statement in statements]
           statement_text = "\n".join(statement_strings)
           messagebox.showinfo("Statements", statement_text)
        else:
           messagebox.showinfo("Statements", "No statements available")


    def logout(self):
        conn = sqlite3.connect("admin_database.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logged_users WHERE number=?", (self.user.number,))
        conn.commit()
        conn.close()

        self.frame.destroy()
        app.show_initial_interface()

class Transaction:
    def __init__(self, sender, recipient_number, amount):
        self.sender = sender
        self.recipient_number = recipient_number
        self.amount = amount

    def is_recipient_registered(self):
        # Check if the recipient number is in the user database
        return self.sender.user_db.is_user_registered(self.recipient_number)

class AdminDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptocurrency Wallet - Admin Dashboard")

        self.show_dashboard()

    def show_dashboard(self):
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.configure(style="Custom.TFrame")
        self.frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.users_button = ttk.Button(self.frame, text="View Logged Users", command=self.view_logged_users)
        self.users_button.grid(row=0, column=0, padx=10, pady=5)

        self.register_button = ttk.Button(self.frame, text="View Registered Users", command=self.view_registered_users)
        self.register_button.grid(row=0, column=1, padx=10, pady=5)

        self.logout_button = ttk.Button(self.frame, text="Logout", command=self.logout)
        self.logout_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    def view_logged_users(self):
        conn = sqlite3.connect("admin_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logged_users")
        logged_users = cursor.fetchall()
        conn.close()

        messagebox.showinfo("Logged-in Users", f"Logged-in Users:\n{logged_users}")

    def view_registered_users(self):
        conn = sqlite3.connect("user_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        registered_users = cursor.fetchall()
        conn.close()

        messagebox.showinfo("Registered Users", f"Registered Users:\n{registered_users}")

    def logout(self):
        self.frame.destroy()
        app.show_initial_interface()


class WalletApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptocurrency Wallet")
        self.current_user = None

        # Apply a themed style to the application
        style = ttk.Style(root)
        style.theme_use("clam")  # Choose the desired theme from available options

        # Connect to the Ethereum blockchain
        web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/09d0a171861d4065b57489ddee0b2b52"))
        self.web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/09d0a171861d4065b57489ddee0b2b52"))

        # Check if the connection was successful
        if self.web3.is_connected():
            print("Connected to the Ethereum blockchain")
        else:
            print("Failed to connect to the Ethereum blockchain")

        # Load the logo image
        logo_path = "/home/kali/Downloads/JK.png"  # Replace with the path to your own logo image
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((200, 200))  # Resize the logo image as desired
        self.logo_photo = ImageTk.PhotoImage(logo_image)

        self.show_initial_interface()

    def show_initial_interface(self):
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.configure(style="Custom.TFrame")
        self.frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.label_logo = ttk.Label(self.frame, image=self.logo_photo)
        self.label_logo.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        self.login_button = ttk.Button(self.frame, text="Login", command=self.show_login_frame)
        self.login_button.grid(row=1, column=0, padx=10, pady=5)

        self.register_button = ttk.Button(self.frame, text="Register", command=self.show_register_frame)
        self.register_button.grid(row=1, column=1, padx=10, pady=5)

    def show_login_frame(self):
        self.frame.destroy()

        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.configure(style="Custom.TFrame")
        self.login_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.login_number_label = ttk.Label(self.login_frame, text="Phone Number:")
        self.login_number_label.grid(row=0, column=0, padx=10, pady=5)

        self.login_number_entry = ttk.Entry(self.login_frame, width=40)
        self.login_number_entry.grid(row=0, column=1, padx=10, pady=5)

        self.login_password_label = ttk.Label(self.login_frame, text="Password:")
        self.login_password_label.grid(row=1, column=0, padx=10, pady=5)

        self.login_password_entry = ttk.Entry(self.login_frame, width=40, show="*")
        self.login_password_entry.grid(row=1, column=1, padx=10, pady=5)

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

        self.back_button = ttk.Button(self.login_frame, text="Back", command=self.back_to_initial)
        self.back_button.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def show_register_frame(self):
        self.frame.destroy()

        self.register_frame = ttk.Frame(self.root, padding=20)
        self.register_frame.configure(style="Custom.TFrame")
        self.register_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.register_number_label = ttk.Label(self.register_frame, text="Phone Number:")
        self.register_number_label.grid(row=0, column=0, padx=10, pady=5)

        self.register_number_entry = ttk.Entry(self.register_frame, width=40)
        self.register_number_entry.grid(row=0, column=1, padx=10, pady=5)

        self.register_name_label = ttk.Label(self.register_frame, text="Name:")
        self.register_name_label.grid(row=1, column=0, padx=10, pady=5)

        self.register_name_entry = ttk.Entry(self.register_frame, width=40)
        self.register_name_entry.grid(row=1, column=1, padx=10, pady=5)

        self.register_address_label = ttk.Label(self.register_frame, text="Address:")
        self.register_address_label.grid(row=2, column=0, padx=10, pady=5)

        self.register_address_entry = ttk.Entry(self.register_frame, width=40)
        self.register_address_entry.grid(row=2, column=1, padx=10, pady=5)

        self.register_password_label = ttk.Label(self.register_frame, text="Password:")
        self.register_password_label.grid(row=3, column=0, padx=10, pady=5)

        self.register_password_entry = ttk.Entry(self.register_frame, width=40, show="*")
        self.register_password_entry.grid(row=3, column=1, padx=10, pady=5)

        self.register_button = ttk.Button(self.register_frame, text="Register", command=self.register)
        self.register_button.grid(row=4, column=0, columnspan=2, padx=10, pady=5)

        self.back_button = ttk.Button(self.register_frame, text="Back", command=self.back_to_initial)
        self.back_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5)
  

    def login(self):
        number = self.login_number_entry.get()
        password = self.login_password_entry.get()

        if not number or not password:
            messagebox.showerror("Error", "Please enter your phone number and password")
            return

        # Check if the user is an admin
        if number == "admin":
            conn = sqlite3.connect("admin_database.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admin WHERE id=?", (number,))
            admin_data = cursor.fetchone()
            conn.close()

            if admin_data:
                if password == admin_data[1]:
                    self.login_frame.destroy()
                    self.current_user = User(number, "Admin", "", self.web3)
                    self.show_admin_dashboard()
                    return

        # Retrieve user data from the database
        conn = sqlite3.connect("user_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE number=?", (number,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            # Check if the entered password matches the stored password
            conn = sqlite3.connect("user_database.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passwords WHERE number=?", (number,))
            stored_password = cursor.fetchone()
            conn.close()

            if stored_password:
                if password == stored_password[1]:
                    self.login_frame.destroy()
                    self.current_user = User(user_data[0], user_data[1], user_data[2], self.web3)
                    self.show_wallet_dashboard()
                    return

        messagebox.showerror("Error", "Invalid phone number or password")



    def show_balance(self):
        if not self.current_user:
            messagebox.showerror("Error", "You are not logged in.")
            return

        balance = self.current_user.balance  # Get the updated balance
        message = "Your balance: {:.2f} ETH\n".format(balance)


    def show_login_message(self):
        message = f"Welcome back, {self.user.name}! You have received money in your account."
        messagebox.showinfo("Login", message)

    def register(self):
        number = self.register_number_entry.get()
        name = self.register_name_entry.get()
        address = self.register_address_entry.get()
        password = self.register_password_entry.get()

        if not number or not name or not address or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        # Check if the user is already registered
        conn = sqlite3.connect("user_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE number=?", (number,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            messagebox.showerror("Error", "User already registered")
            return

        
        # Create a new Wallet object and set the initial balance to 0
        user_wallet = Wallet(self.web3)
        user_wallet.balance = 0

    # Save user data to the database
        conn = sqlite3.connect("user_database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (number, name, address))
        cursor.execute("INSERT INTO passwords VALUES (?, ?)", (number, password))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "User registered successfully")
        self.show_initial_interface()

        
    def generate_ethereum_address(self):
        if self.current_user and hasattr(self.current_user, 'wallet'):
            address = self.current_user.wallet.hdwallet.generate_ethereum_address()
            return address
        else:
            messagebox.showerror("Error", "User wallet not found.")
            return None
        
        # Get the balance of the wallet for the new user
        balance = self.current_user.get_balance()

        # Show a message with the initial balance
        messagebox.showinfo("Success", f"User registered successfully.\nInitial Wallet Balance: {balance}")

    def confirm_transaction(self):
        # ...
        if user_entered_otp == self.transaction_otp:
            success = True
            message = "Transaction successful! Amount transferred."

            # Update sender's balance
            self.current_user.balance -= amount

            # Update recipient's balance if recipient is registered
            if self.transaction.is_recipient_registered():
                recipient_user = self.user_db.get_user_by_number(self.transaction.recipient_number)
                recipient_user.balance += amount
                self.user_db.update_user_balance(recipient_user.number, recipient_user.balance)
        else:
            success = False
            message = "Transaction failed. Invalid OTP."
        
    def show_wallet_dashboard(self):
        self.wallet_dashboard = WalletDashboard(self.root, self.current_user)

    def show_admin_dashboard(self):
        self.admin_dashboard = AdminDashboard(self.root)

    def back_to_initial(self):
        if hasattr(self, "login_frame"):
            self.login_frame.destroy()
        elif hasattr(self, "register_frame"):
            self.register_frame.destroy()

        self.show_initial_interface()


# Create the main application window
root = tk.Tk()

# Run the application
app = WalletApp(root)
root.mainloop()
