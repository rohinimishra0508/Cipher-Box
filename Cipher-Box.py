import os
import sqlite3
import base64
import hashlib
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from fileCompress import decrypt_compressed_file, encrypt_compressed_file

# Path to the SQLite database
DB_PATH = "user_db.sqlite"

# Initialize the SQLite database and create users table if it doesn't exist
def initialize_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Generate a key from the password using base64 encoding for Fernet
def generate_fernet_key(password):
    return base64.urlsafe_b64encode(password.ljust(32)[:32].encode())

# Generate a key for AES encryption (128-bit key)
def generate_aes_key(password):
    return hashlib.sha256(password.encode()).digest()[:16]

# Encrypt a file using Fernet
def encrypt_file_fernet(file_path, key):
    # with open(file_path, 'rb') as f:
    #     data = f.read()
    # encrypted_data = Fernet(key).encrypt(data)
    # encrypted_file_path = file_path + ".encrypted"
    # with open(encrypted_file_path, 'wb') as f:
    #     f.write(encrypted_data)
    # return encrypted_file_path
    return encrypt_compressed_file(file_path,key)

# Decrypt a file using Fernet
def decrypt_file_fernet(file_path, key):
    # with open(file_path, 'rb') as f:
    #     encrypted_data = f.read()
    # decrypted_data = Fernet(key).decrypt(encrypted_data)
    # new_file_path = file_path.replace(".encrypted", "")

    # # Split the file path into name and extension
    # file_name, file_extension = os.path.splitext(new_file_path)

    # # Generate a new file name by adding "_decrypted" before the extension
    # decrypted_file_path = f"{file_name}_Fdecrypted{file_extension}"

    # with open(decrypted_file_path, 'wb') as f:
    #     f.write(decrypted_data)
    # return decrypted_file_path
    return decrypt_compressed_file(file_path, key)

# Encrypt a file using AES
def encrypt_file_aes(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_file_path = file_path + ".aes"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    return encrypted_file_path

# Decrypt a file using AES
def decrypt_file_aes(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    new_file_path = file_path.replace(".aes", "")

    # Split the file path into name and extension
    file_name, file_extension = os.path.splitext(new_file_path)

    # Generate a new file name by adding "_decrypted" before the extension
    decrypted_file_path = f"{file_name}_AESdecrypted{file_extension}"

    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return decrypted_file_path

# Check if the user exists and validate credentials
def validate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    stored_pass = cursor.fetchone()
    conn.close()
    if stored_pass and hashlib.sha256(password.encode()).hexdigest() == stored_pass[0]:
        return True
    return False

# Register a new user
def register_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        messagebox.showerror("Error", "Username already exists")
        conn.close()
        return

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "User registered successfully")

# Function to select files
def select_files():
    files = filedialog.askopenfilenames(title="Select Files")
    file_list.delete(0, END)
    for file in files:
        file_list.insert(END, file)

# Function to encrypt selected files
def encrypt_files():
    if not current_user:
        messagebox.showerror("Error", "Please log in first")
        return

    password = code.get()
    algorithm = selected_algorithm.get()
    if not password:
        messagebox.showerror("Error", "Please enter the password")
        return

    if algorithm == "Fernet":
        key = generate_fernet_key(password)
        for file_path in file_list.get(0, END):
            try:
                encrypted_file_path = encrypt_file_fernet(file_path, key)
                messagebox.showinfo("Success", f"File {encrypted_file_path} encrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt {file_path}\n{str(e)}")
    elif algorithm == "AES":
        key = generate_aes_key(password)
        for file_path in file_list.get(0, END):
            try:
                encrypted_file_path = encrypt_file_aes(file_path, key)
                messagebox.showinfo("Success", f"File {encrypted_file_path} encrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt {file_path}\n{str(e)}")

# Function to decrypt selected files
def decrypt_files():
    if not current_user:
        messagebox.showerror("Error", "Please log in first")
        return

    password = code.get()
    algorithm = selected_algorithm.get()
    if not password:
        messagebox.showerror("Error", "Please enter the password")
        return

    if algorithm == "Fernet":
        key = generate_fernet_key(password)
        for file_path in file_list.get(0, END):
            try:
                decrypted_file_path = decrypt_file_fernet(file_path, key)
                messagebox.showinfo("Success", f"File {decrypted_file_path} decrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt {file_path}\n{str(e)}")
    elif algorithm == "AES":
        key = generate_aes_key(password)
        for file_path in file_list.get(0, END):
            try:
                decrypted_file_path = decrypt_file_aes(file_path, key)
                messagebox.showinfo("Success", f"File {decrypted_file_path} decrypted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt {file_path}\n{str(e)}")

# Function to handle user registration
def register():
    username = username_entry.get()
    password = password_entry.get()
    if username and password:
        register_user(username, password)
    else:
        messagebox.showerror("Error", "Please enter both username and password")

# Function to handle user login
def login():
    username = username_entry.get()
    password = password_entry.get()
    if validate_user(username, password):
        global current_user
        current_user = username
        messagebox.showinfo("Success", f"Welcome, {username}!")
        login_window.destroy()
    else:
        messagebox.showerror("Error", "Invalid username or password")

# Initialize Tkinter window
screen = Tk()
screen.geometry("450x500")
screen.title("File Encryption and Decryption Tool")
screen.configure(bg="lightblue")

# Create login and registration window
def open_login_window():
    global login_window, username_entry, password_entry
    login_window = Toplevel(screen)
    login_window.geometry("300x240")
    login_window.title("Login/Register")
    login_window.configure(bg="lightblue")

    Label(login_window, text="Username", font="impack 12 bold").pack(pady=5)
    username_entry = Entry(login_window, bd=2, font="12")
    username_entry.pack(pady=5)

    Label(login_window, text="Password", font="impack 12 bold").pack(pady=5)
    password_entry = Entry(login_window, bd=2, font="12", show="*")
    password_entry.pack(pady=5)

    Button(login_window, text="Register", font="arial 12 bold", command=register).pack(pady=5)
    Button(login_window, text="Login", font="arial 12 bold", command=login).pack(pady=5)

# Label for password entry
Label(screen, text="Enter secret key", font="impack 14 bold").place(x=150, y=10)
code = StringVar()
Entry(textvariable=code, bd=4, font="20", show="*").place(x=133, y=40)

# Option to select encryption algorithm
Label(screen, text="Select Algorithm", font="impack 14 bold").place(x=150, y=80)
selected_algorithm = StringVar(value="Fernet")
Radiobutton(screen, text="Fernet", variable=selected_algorithm, value="Fernet").place(x=160, y=115)
Radiobutton(screen, text="AES", variable=selected_algorithm, value="AES").place(x=245, y=115)

# Listbox to display selected files
file_list = Listbox(screen, bd=4, font="20")
file_list.place(x=10, y=220, width=430, height=120)

# Buttons to select files, encrypt, and decrypt
Button(screen, text="Select Files", font="arial 15 bold", fg="black", command=select_files).place(x=158, y=175)
Button(screen, text="ENCRYPT", font="arial 15 bold", bg="red", fg="white", command=encrypt_files).place(x=50, y=350, width=150)
Button(screen, text="DECRYPT", font="arial 15 bold", bg="green", fg="white", command=decrypt_files).place(x=250, y=350, width=150)

# Initialize the database
initialize_db()

# Open login window when the application starts
open_login_window()

# Start the Tkinter main loop
mainloop()