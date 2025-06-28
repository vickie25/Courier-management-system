import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import re
from datetime import datetime

class UserManager:
    def __init__(self, db_name="courier_system.db"):
        self.db_name = db_name
        self.create_tables()

    def create_tables(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('Admin', 'Courier', 'Client')),
                    user_id TEXT UNIQUE
                )
            ''')
            # Orders table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS orders (
                    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    courier_id TEXT,
                    product TEXT,
                    status TEXT CHECK(status IN ('Waiting', 'Dispatched', 'In-Progress', 'Delivered')),
                    created_at TEXT,
                    FOREIGN KEY (client_id) REFERENCES users(user_id),
                    FOREIGN KEY (courier_id) REFERENCES users(user_id)
                )
            ''')
            conn.commit()

    def generate_id(self, role):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE role = ?", (role,))
            ids = [row[0] for row in cursor.fetchall()]
            prefix = "COU" if role == "Courier" else "CLI"
            num = len(ids) + 1
            return f"{prefix}{num:03d}"

    def signup(self, username, password, role, user_id=None):
        if not username or not password:
            return False, "Username and password cannot be empty."
        if not re.match(r"^[a-zA-Z0-9_]{4,}$", username):
            return False, "Username must be at least 4 characters and contain only letters, numbers, or underscores."
        if len(password) < 6:
            return False, "Password must be at least 6 characters."
        
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            try:
                if role == "Admin":
                    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
                    if cursor.fetchone()[0] > 0:
                        return False, "An admin already exists."
                    user_id = "ADMIN001"
                else:
                    user_id = user_id or self.generate_id(role)
                cursor.execute("INSERT INTO users (username, password, role, user_id) VALUES (?, ?, ?, ?)",
                               (username, password, role, user_id))
                conn.commit()
                return True, f"{role} created successfully with ID: {user_id}"
            except sqlite3.IntegrityError:
                return False, "Username or ID already exists."

    def login(self, username, password):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT role, user_id FROM users WHERE username = ? AND password = ?",
                           (username, password))
            result = cursor.fetchone()
            if result:
                return True, result[0], result[1]
            return False, "Invalid username or password.", None

class OrderManager:
    def __init__(self, db_name="courier_system.db"):
        self.db_name = db_name

    def create_order(self, client_id, product):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO orders (client_id, product, status, created_at) VALUES (?, ?, ?, ?)",
                               (client_id, product, "Waiting", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                return True, "Order created successfully."
            except sqlite3.IntegrityError:
                return False, "Invalid client ID."

    def update_order_status(self, order_id, status, courier_id=None):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            try:
                if courier_id:
                    cursor.execute("UPDATE orders SET status = ?, courier_id = ? WHERE order_id = ?",
                                   (status, courier_id, order_id))
                else:
                    cursor.execute("UPDATE orders SET status = ? WHERE order_id = ?",
                                   (status, order_id))
                conn.commit()
                return True, "Order status updated."
            except sqlite3.Error:
                return False, "Failed to update order status."

    def get_orders(self, role=None, user_id=None, status_filter=None):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            query = "SELECT order_id, client_id, courier_id, product, status, created_at FROM orders"
            params = []
            if role == "Client":
                query += " WHERE client_id = ?"
                params.append(user_id)
            elif role == "Courier":
                query += " WHERE courier_id = ?"
                params.append(user_id)
            if status_filter:
                query += " WHERE" if "WHERE" not in query else " AND"
                query += " status = ?"
                params.append(status_filter)
            cursor.execute(query, params)
            return cursor.fetchall()

class CourierManagementSystem:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Courier Management System")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        self.user_manager = UserManager()
        self.order_manager = OrderManager()
        self.current_user = None
        self.current_user_id = None
        self.current_frame = None
        self.show_login()

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.current_frame.pack(fill="both", expand=True, padx=20, pady=20)

    def show_login(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="Courier Management System", font=("Arial", 20, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tk.Label(self.current_frame, text="Username", bg="#f0f0f0").pack()
        username_entry = tk.Entry(self.current_frame)
        username_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="Password", bg="#f0f0f0").pack()
        password_entry = tk.Entry(self.current_frame, show="*")
        password_entry.pack(pady=5)
        
        tk.Button(self.current_frame, text="Login", command=lambda: self.handle_login(username_entry.get(), password_entry.get())).pack(pady=10)
        tk.Button(self.current_frame, text="Sign Up", command=self.show_signup).pack(pady=5)

    def show_signup(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="Sign Up", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tk.Label(self.current_frame, text="Username", bg="#f0f0f0").pack()
        username_entry = tk.Entry(self.current_frame)
        username_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="Password", bg="#f0f0f0").pack()
        password_entry = tk.Entry(self.current_frame, show="*")
        password_entry.pack(pady=5)
        
        role_var = tk.StringVar(value="Admin")
        tk.Label(self.current_frame, text="Role", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Admin", variable=role_var, value="Admin", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Courier", variable=role_var, value="Courier", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Client", variable=role_var, value="Client", bg="#f0f0f0").pack()
        
        tk.Button(self.current_frame, text="Register", command=lambda: self.handle_signup(username_entry.get(), password_entry.get(), role_var.get())).pack(pady=10)
        tk.Button(self.current_frame, text="Back to Login", command=self.show_login).pack(pady=5)

    def handle_signup(self, username, password, role):
        success, message = self.user_manager.signup(username, password, role)
        messagebox.showinfo("Sign Up", message)
        if success:
            if role == "Admin":
                self.show_login()
            else:
                self.show_admin_dashboard()

    def handle_login(self, username, password):
        success, message, role = self.user_manager.login(username, password)
        messagebox.showinfo("Login", message)
        if success:
            self.current_user = role
            self.current_user_id = self.user_manager.login(username, password)[2]
            if role == "Admin":
                self.show_admin_dashboard()
            elif role == "Courier":
                self.show_courier_dashboard()
            else:
                self.show_client_dashboard()

    def show_admin_dashboard(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="Admin Dashboard", font=("Arial", 18, "bold"), bg="#f0f0f0").pack(pady=10)
        
        menubar = tk.Menu(self.current_frame)
        self.root.config(menu=menubar)
        nav_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Navigation", menu=nav_menu)
        nav_menu.add_command(label="Create Courier", command=self.show_create_courier)
        nav_menu.add_command(label="Create Client", command=self.show_create_client)
        nav_menu.add_command(label="View Users", command=self.show_users)
        nav_menu.add_command(label="View Orders", command=self.show_all_orders)
        nav_menu.add_command(label="Logout", command=self.show_login)
        
        tk.Button(self.current_frame, text="Create Courier", command=self.show_create_courier).pack(pady=5)
        tk.Button(self.current_frame, text="Create Client", command=self.show_create_client).pack(pady=5)
        tk.Button(self.current_frame, text="View Users", command=self.show_users).pack(pady=5)
        tk.Button(self.current_frame, text="View Orders", command=self.show_all_orders).pack(pady=5)

    def show_create_courier(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="Create Courier", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tk.Label(self.current_frame, text="Username", bg="#f0f0f0").pack()
        username_entry = tk.Entry(self.current_frame)
        username_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="Password", bg="#f0f0f0").pack()
        password_entry = tk.Entry(self.current_frame, show="*")
        password_entry.pack(pady=5)
        
        tk.Button(self.current_frame, text="Create", command=lambda: self.handle_create_courier(username_entry.get(), password_entry.get())).pack(pady=10)
        tk.Button(self.current_frame, text="Back", command=self.show_admin_dashboard).pack(pady=5)

    def handle_create_courier(self, username, password):
        success, message = self.user_manager.signup(username, password, "Courier")
        messagebox.showinfo("Create Courier", message)
        if success:
            self.show_admin_dashboard()

    def show_create_client(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="Create Client", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tk.Label(self.current_frame, text="Username", bg="#f0f0f0").pack()
        username_entry = tk.Entry(self.current_frame)
        username_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="Password", bg="#f0f0f0").pack()
        password_entry = tk.Entry(self.current_frame, show="*")
        password_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="Product for Order", bg="#f0f0f0").pack()
        product_entry = tk.Entry(self.current_frame)
        product_entry.pack(pady=5)
        
        tk.Button(self.current_frame, text="Create", command=lambda: self.handle_create_client(username_entry.get(), password_entry.get(), product_entry.get())).pack(pady=10)
        tk.Button(self.current_frame, text="Back", command=self.show_admin_dashboard).pack(pady=5)

    def handle_create_client(self, username, password, product):
        success, message = self.user_manager.signup(username, password, "Client")
        if success:
            client_id = self.user_manager.generate_id("Client")
            self.user_manager.signup(username, password, "Client", client_id)
            if product:
                self.order_manager.create_order(client_id, product)
            messagebox.showinfo("Create Client", message)
            self.show_admin_dashboard()
        else:
            messagebox.showerror("Error", message)

    def show_users(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="All Users", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tree = ttk.Treeview(self.current_frame, columns=("Username", "Role", "User ID"), show="headings")
        tree.heading("Username", text="Username")
        tree.heading("Role", text="Role")
        tree.heading("User ID", text="User ID")
        tree.pack(fill="both", expand=True)
        
        with sqlite3.connect(self.user_manager.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, role, user_id FROM users")
            for row in cursor.fetchall():
                tree.insert("", "end", values=row)
        
        tk.Button(self.current_frame, text="Back", command=self.show_admin_dashboard).pack(pady=10)

    def show_all_orders(self):
        self.clear_frame()
        tk.Label(self.current_frame, text="All Orders", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tree = ttk.Treeview(self.current_frame, columns=("Order ID", "Client ID", "Courier ID", "Product", "Status", "Created At"), show="headings")
        tree.heading("Order ID", text="Order ID")
        tree.heading("Client ID", text="Client ID")
        tree.heading("Courier ID", text="Courier ID")
        tree.heading("Product", text="Product")
        tree.heading("Status", text="Status")
        tree.heading("Created At", text="Created At")
        tree.pack(fill="both", expand=True)
        
        orders = self.order_manager.get_orders()
        for order in orders:
            tree.insert("", "end", values=order)
        
        tk.Button(self.current_frame, text="Back", command=self.show_admin_dashboard).pack(pady=10)

    def show_courier_dashboard(self):
        self.clear_frame()
        tk.Label(self.current_frame, text=f"Courier Dashboard (ID: {self.current_user_id})", font=("Arial", 18, "bold"), bg="#f0f0f0").pack(pady=10)
        
        menubar = tk.Menu(self.current_frame)
        self.root.config(menu=menubar)
        nav_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Navigation", menu=nav_menu)
        nav_menu.add_command(label="View Assigned Orders", command=self.show_courier_orders)
        nav_menu.add_command(label="Logout", command=self.show_login)
        
        status_var = tk.StringVar(value="All")
        tk.Label(self.current_frame, text="Filter Orders by Status", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="All", variable=status_var, value="All", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Waiting", variable=status_var, value="Waiting", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Dispatched", variable=status_var, value="Dispatched", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="In-Progress", variable=status_var, value="In-Progress", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Delivered", variable=status_var, value="Delivered", bg="#f0f0f0").pack()
        
        tk.Button(self.current_frame, text="View Orders", command=lambda: self.show_courier_orders(status_var.get())).pack(pady=10)

    def show_courier_orders(self, status_filter=None):
        self.clear_frame()
        tk.Label(self.current_frame, text="Assigned Orders", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tree = ttk.Treeview(self.current_frame, columns=("Order ID", "Client ID", "Product", "Status", "Created At"), show="headings")
        tree.heading("Order ID", text="Order ID")
        tree.heading("Client ID", text="Client ID")
        tree.heading("Product", text="Product")
        tree.heading("Status", text="Status")
        tree.heading("Created At", text="Created At")
        tree.pack(fill="both", expand=True)
        
        status_filter = None if status_filter == "All" else status_filter
        orders = self.order_manager.get_orders("Courier", self.current_user_id, status_filter)
        for order in orders:
            tree.insert("", "end", values=(order[0], order[1], order[3], order[4], order[5]))
        
        tk.Label(self.current_frame, text="Order ID", bg="#f0f0f0").pack()
        order_id_entry = tk.Entry(self.current_frame)
        order_id_entry.pack(pady=5)
        
        tk.Label(self.current_frame, text="New Status", bg="#f0f0f0").pack()
        status_var = tk.StringVar(value="Dispatched")
        tk.OptionMenu(self.current_frame, status_var, "Dispatched", "In-Progress", "Delivered").pack(pady=5)
        
        tk.Button(self.current_frame, text="Update Status", command=lambda: self.handle_update_status(order_id_entry.get(), status_var.get())).pack(pady=10)
        tk.Button(self.current_frame, text="Back", command=self.show_courier_dashboard).pack(pady=5)

    def handle_update_status(self, order_id, status):
        success, message = self.order_manager.update_order_status(order_id, status, self.current_user_id)
        messagebox.showinfo("Update Status", message)
        if success:
            self.show_courier_orders()

    def show_client_dashboard(self):
        self.clear_frame()
        tk.Label(self.current_frame, text=f"Client Dashboard (ID: {self.current_user_id})", font=("Arial", 18, "bold"), bg="#f0f0f0").pack(pady=10)
        
        menubar = tk.Menu(self.current_frame)
        self.root.config(menu=menubar)
        nav_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Navigation", menu=nav_menu)
        nav_menu.add_command(label="View Orders", command=self.show_client_orders)
        nav_menu.add_command(label="Logout", command=self.show_login)
        
        status_var = tk.StringVar(value="All")
        tk.Label(self.current_frame, text="Filter Orders by Status", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="All", variable=status_var, value="All", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Waiting", variable=status_var, value="Waiting", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="In-Transit", variable=status_var, value="In-Progress", bg="#f0f0f0").pack()
        tk.Radiobutton(self.current_frame, text="Completed", variable=status_var, value="Delivered", bg="#f0f0f0").pack()
        
        tk.Button(self.current_frame, text="View Orders", command=lambda: self.show_client_orders(status_var.get())).pack(pady=10)

    def show_client_orders(self, status_filter=None):
        self.clear_frame()
        tk.Label(self.current_frame, text="Your Orders", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=20)
        
        tree = ttk.Treeview(self.current_frame, columns=("Order ID", "Courier ID", "Product", "Status", "Created At"), show="headings")
        tree.heading("Order ID", text="Order ID")
        tree.heading("Courier ID", text="Courier ID")
        tree.heading("Product", text="Product")
        tree.heading("Status", text="Status")
        tree.heading("Created At", text="Created At")
        tree.pack(fill="both", expand=True)
        
        status_filter = None if status_filter == "All" else status_filter
        orders = self.order_manager.get_orders("Client", self.current_user_id, status_filter)
        for order in orders:
            tree.insert("", "end", values=(order[0], order[2], order[3], order[4], order[5]))
        
        tk.Button(self.current_frame, text="Back", command=self.show_client_dashboard).pack(pady=10)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = CourierManagementSystem()
    app.run()
