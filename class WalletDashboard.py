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