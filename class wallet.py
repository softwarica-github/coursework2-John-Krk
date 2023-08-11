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
