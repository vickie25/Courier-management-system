import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import bcrypt
import re


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# --- The DB ---
try:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
except sqlite3.Error as e:
    messagebox.showerror("Database Error", f"Error connecting to database: {e}")
    exit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password BLOB NOT NULL
)
""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS deliveries (
    package_id TEXT PRIMARY KEY,
    courier TEXT,
    customer TEXT,
    status TEXT NOT NULL
)
""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()



def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def register_user():
    role = register_role.get()
    full_name = register_full_name.get().strip()
    username = register_username.get().strip()
    email = register_email.get().strip()
    password = register_password.get()

    if not role or not full_name or not username or not email or not password:
        messagebox.showerror("Error", "All fields are required.")
        return

    if len(password) < 6:
        messagebox.showerror("Error", "Password must be at least 6 characters long.")
        return

    if not is_valid_email(email):
        messagebox.showerror("Error", "Invalid email address.")
        return

    hashed = hash_password(password)

    try:
        cursor.execute(
            "INSERT INTO users (role, full_name, username, email, password) VALUES (?, ?, ?, ?, ?)",
            (role, full_name, username, email, hashed)
        )
        conn.commit()
        messagebox.showinfo("Success", f"{role} registered successfully! Please log in.")
        notebook.select(login_tab)  
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")


def login_user():
    role = login_role.get()
    username = login_username.get().strip()
    password = login_password.get()

    if not role or not username or not password:
        messagebox.showerror("Error", "All fields are required.")
        return

    cursor.execute("SELECT password FROM users WHERE role = ? AND username = ?", (role, username))
    user = cursor.fetchone()

    if user and check_password(password, user[0]):
        messagebox.showinfo("Login Success", f"Welcome, {username} ({role})!")
        open_dashboard(username, role)
    else:
        messagebox.showerror("Login Failed", "Invalid credentials.")

def open_dashboard(username, role):
    dashboard = tk.Toplevel(root)
    dashboard.title(f"{role} Dashboard")
    dashboard.geometry("400x250")

    tk.Label(dashboard, text=f"Welcome, {username}!", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2)

    if role == "Admin":
        tk.Label(dashboard, text="Admin Dashboard").grid(row=1, column=0, columnspan=2)
        tk.Button(dashboard, text="View All Users", command=view_all_users).grid(row=2, column=0)
        tk.Button(dashboard, text="System Settings").grid(row=2, column=1)
    
    elif role == "Courier":
        tk.Label(dashboard, text="Courier Dashboard").grid(row=1, column=0, columnspan=2)
        tk.Button(dashboard, text="My Deliveries").grid(row=2, column=0)
        tk.Button(dashboard, text="Update Delivery Status").grid(row=2, column=1)

    elif role == "Customer":
        tk.Label(dashboard, text="Customer Dashboard").grid(row=1, column=0, columnspan=2)
        tk.Button(dashboard, text="Track My Package", command=track_package).grid(row=2, column=0)
        tk.Button(dashboard, text="Request Pickup", command=request_pickup).grid(row=2, column=1)
        tk.Button(dashboard, text="My Deliveries", command=my_deliveries).grid(row=3, column=0)
        tk.Button(dashboard, text="New Delivery", command=new_delivery).grid(row=3, column=1)
        tk.Button(dashboard, text="Edit Profile", command=lambda: edit_profile(username)).grid(row=4, column=0)
        tk.Button(dashboard, text="Give Feedback", command=give_feedback).grid(row=5, column=0)


    tk.Button(dashboard, text="Logout", command=dashboard.destroy).grid(row=3, column=0, columnspan=2)

def view_all_users():
    view_win = tk.Toplevel(root)
    view_win.title("All Registered Users")
    view_win.geometry("400x250")

    tk.Label(view_win, text="All Users:", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2)

    cursor.execute("SELECT role, full_name, username, email FROM users ORDER BY role")
    all_users = cursor.fetchall()

    for i, user in enumerate(all_users, start=1):
        tk.Label(view_win, text=f"{user[0]} - {user[1]} ({user[2]}) - {user[3]}").grid(row=i, column=0, columnspan=2)

def track_package():
    win = tk.Toplevel(root)
    win.title("Track My Package")

    tk.Label(win, text="Enter Package ID:").grid(row=0, column=0)
    package_entry = tk.Entry(win)
    package_entry.grid(row=0, column=1)

    result_label = tk.Label(win, text="")
    result_label.grid(row=2, column=0, columnspan=2)

    def track():
        package_id = package_entry.get().strip()
        if not package_id:
            result_label.config(text="Please enter a package ID.")
            return

        cursor.execute("SELECT status FROM deliveries WHERE package_id = ?", (package_id,))
        result = cursor.fetchone()
        if result:
            result_label.config(text=f"Status: {result[0]}")
        else:
            result_label.config(text="Package not found.")

    tk.Button(win, text="Track", command=track).grid(row=1, column=1, sticky="e")

def request_pickup():
    win = tk.Toplevel(root)
    win.title("Request Pickup")

    tk.Label(win, text="Pickup Address:").grid(row=0, column=0)
    address_entry = tk.Entry(win, width=40)
    address_entry.grid(row=0, column=1)

    tk.Label(win, text="Preferred Time:").grid(row=1, column=0)
    time_entry = tk.Entry(win)
    time_entry.grid(row=1, column=1)

    def submit():
        address = address_entry.get()
        time = time_entry.get()
        if not address or not time:
            messagebox.showerror("Error", "All fields are required.")
            return
        messagebox.showinfo("Request Submitted", "Pickup request sent successfully!")

    tk.Button(win, text="Submit", command=submit).grid(row=2, column=1, sticky="e")

def my_deliveries():
    win = tk.Toplevel(root)
    win.title("My Deliveries")

    tk.Label(win, text="Your Deliveries:", font=("Arial", 12)).grid(row=0, column=0, columnspan=2)

    cursor.execute("SELECT package_id, status FROM deliveries WHERE customer = ?", (login_username.get(),))
    deliveries = cursor.fetchall()

    if not deliveries:
        tk.Label(win, text="No deliveries found.").grid(row=1, column=0)
    else:
        for i, (pid, status) in enumerate(deliveries, start=1):
            tk.Label(win, text=f"Package ID: {pid}").grid(row=i, column=0)
            tk.Label(win, text=f"Status: {status}").grid(row=i, column=1)

def new_delivery():
    win = tk.Toplevel(root)
    win.title("New Delivery Request")

    tk.Label(win, text="Package ID:").grid(row=0, column=0)
    pid_entry = tk.Entry(win)
    pid_entry.grid(row=0, column=1)

    tk.Label(win, text="Recipient Name:").grid(row=1, column=0)
    recipient_entry = tk.Entry(win)
    recipient_entry.grid(row=1, column=1)

    def submit():
        pid = pid_entry.get().strip()
        recipient = recipient_entry.get().strip()
        if not pid or not recipient:
            messagebox.showerror("Error", "All fields are required.")
            return
        try:
            cursor.execute("INSERT INTO deliveries (package_id, courier, customer, status) VALUES (?, ?, ?, ?)",
                           (pid, "", login_username.get(), "Requested"))
            conn.commit()
            messagebox.showinfo("Success", "New delivery created!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Package ID already exists.")

    tk.Button(win, text="Submit", command=submit).grid(row=3, column=1, sticky="e")

def edit_profile(username):
    win = tk.Toplevel(root)
    win.title("Edit Profile")

    cursor.execute("SELECT full_name, email FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if not result:
        messagebox.showerror("Error", "User not found.")
        return

    tk.Label(win, text="Full Name:").grid(row=0, column=0)
    name_entry = tk.Entry(win)
    name_entry.insert(0, result[0])
    name_entry.grid(row=0, column=1)

    tk.Label(win, text="Email:").grid(row=1, column=0)
    email_entry = tk.Entry(win)
    email_entry.insert(0, result[1])
    email_entry.grid(row=1, column=1)

    def save():
        new_name = name_entry.get().strip()
        new_email = email_entry.get().strip()
        if not new_name or not new_email:
            messagebox.showerror("Error", "All fields are required.")
            return
        cursor.execute("UPDATE users SET full_name = ?, email = ? WHERE username = ?", 
                       (new_name, new_email, username))
        conn.commit()
        messagebox.showinfo("Success", "Profile updated!")

    tk.Button(win, text="Save Changes", command=save).grid(row=2, column=1, sticky="e")

def give_feedback():
    win = tk.Toplevel(root)
    win.title("Give Feedback")

    tk.Label(win, text="We'd love your feedback").grid(row=0, column=0, columnspan=2)

    feedback_text = tk.Text(win, height=6, width=40)
    feedback_text.grid(row=1, column=0, columnspan=2)

    def submit_feedback():
        message = feedback_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Feedback cannot be empty.")
            return

        cursor.execute("INSERT INTO feedback (username, message) VALUES (?, ?)", 
                       (login_username.get(), message))
        conn.commit()
        messagebox.showinfo("Thank you!", "Your feedback has been submitted.")
        win.destroy()

    tk.Button(win, text="Submit", command=submit_feedback).grid(row=2, column=1, sticky="e")



root = tk.Tk()
root.title("Courier Management System - Login/Register")
root.geometry("400x400")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')


register_tab = tk.Frame(notebook)
notebook.add(register_tab, text="Register")

tk.Label(register_tab, text="Role:").grid(row=0, column=0, sticky="w", padx=10)
register_role = ttk.Combobox(register_tab, values=["Admin", "Courier", "Customer"], state="readonly")
register_role.grid(row=0, column=1)
register_role.current(0)

tk.Label(register_tab, text="Full Name:").grid(row=1, column=0, sticky="w", padx=10)
register_full_name = tk.Entry(register_tab)
register_full_name.grid(row=1, column=1)

tk.Label(register_tab, text="Username:").grid(row=2, column=0, sticky="w", padx=10)
register_username = tk.Entry(register_tab)
register_username.grid(row=2, column=1)

tk.Label(register_tab, text="Email:").grid(row=3, column=0, sticky="w", padx=10)
register_email = tk.Entry(register_tab)
register_email.grid(row=3, column=1)

tk.Label(register_tab, text="Password:").grid(row=4, column=0, sticky="w", padx=10)
register_password = tk.Entry(register_tab, show="*")
register_password.grid(row=4, column=1)

tk.Button(register_tab, text="Register", command=register_user).grid(row=5, column=1, sticky="e")


login_tab = tk.Frame(notebook)
notebook.add(login_tab, text="Login")

tk.Label(login_tab, text="Role:").grid(row=0, column=0, sticky="w", padx=10)
login_role = ttk.Combobox(login_tab, values=["Admin", "Courier", "Customer"], state="readonly")
login_role.grid(row=0, column=1)
login_role.current(0)

tk.Label(login_tab, text="Username:").grid(row=1, column=0, sticky="w", padx=10)
login_username = tk.Entry(login_tab)
login_username.grid(row=1, column=1)

tk.Label(login_tab, text="Password:").grid(row=2, column=0, sticky="w", padx=10)
login_password = tk.Entry(login_tab, show="*")
login_password.grid(row=2, column=1)

tk.Button(login_tab, text="Login", command=login_user).grid(row=3, column=1, sticky="e")


root.mainloop()
conn.close()
