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


