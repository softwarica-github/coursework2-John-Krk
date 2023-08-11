
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
