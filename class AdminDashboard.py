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