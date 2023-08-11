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

class TransactionStatement:
    def __init__(self, timestamp, recipient, amount):
        self.timestamp = timestamp
        self.recipient = recipient
        self.amount = amount

    def get_details(self):
        formatted_timestamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"Timestamp: {formatted_timestamp}, Recipient: {self.recipient}, Amount: {self.amount}"

class Transaction:
    def __init__(self, sender, recipient_number, amount):
        self.sender = sender
        self.recipient_number = recipient_number
        self.amount = amount

    def is_recipient_registered(self):
        # Check if the recipient number is in the user database
        return self.sender.user_db.is_user_registered(self.recipient_number)




# Create the main application window
root = tk.Tk()

# Run the application
app = WalletApp(root)
root.mainloop()