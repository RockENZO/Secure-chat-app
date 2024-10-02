import os
import subprocess
import asyncio
import websockets
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import ssl
import signal
import re
import tkinter as tk
from tkinter import scrolledtext, ttk, simpledialog, filedialog
import threading
import uuid
import requests
import webbrowser

# Utility functions for encryption and decryption
def encrypt_private_key(private_key, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(private_key) + padder.finalize()
    encrypted_private_key = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted_private_key

def decrypt_private_key(encrypted_private_key, password):
    salt = encrypted_private_key[:16]
    iv = encrypted_private_key[16:32]
    encrypted_data = encrypted_private_key[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    private_key = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return private_key

# Generate SSL/TLS certificates for the user
def generate_user_certificates(username, user_id, password):
    cert_file = f"{username}_{user_id}_cert.pem"
    key_file = f"{username}_{user_id}_key.pem"
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_file, "-out", cert_file, "-days", "365", "-nodes",
            f"-subj", f"/CN={username}/UID={user_id}"
        ])
        with open(key_file, 'rb') as f:
            private_key = f.read()
        encrypted_private_key = encrypt_private_key(private_key, password)
        with open(key_file, 'wb') as f:
            f.write(encrypted_private_key)
        print(f"SSL/TLS certificates generated for {username} with ID {user_id} and private key encrypted.")
    return cert_file, key_file

def load_user_ssl_context(username, user_id, password):
    cert_file = f"{username}_{user_id}_cert.pem"
    key_file = f"{username}_{user_id}_key.pem"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with open(key_file, 'rb') as f:
        encrypted_private_key = f.read()
    private_key = decrypt_private_key(encrypted_private_key, password)
    
    # Write the decrypted private key to a temporary file
    temp_key_file = f"temp_{username}_{user_id}_key.pem"
    with open(temp_key_file, 'wb') as f:
        f.write(private_key)
    
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=temp_key_file)
    
    # Remove the temporary file after loading the SSL context
    os.remove(temp_key_file)
    
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

def sanitize_input(input_string):
    return re.sub(r'[^\w\s]', '', input_string)

def cleanup(username, user_id):
    cert_file = f"{username}_{user_id}_cert.pem"
    key_file = f"{username}_{user_id}_key.pem"
    if os.path.exists(cert_file):
        os.remove(cert_file)
    if os.path.exists(key_file):
        os.remove(key_file)
    print(f"SSL/TLS certificates removed for {username} with ID {user_id}.")

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Counter for message signing
counter = 0

class ChatGUI:
    def __init__(self, master, username, user_id):
        self.master = master
        self.username = username
        self.user_id = user_id
        self.message_type = "public"  # Track the message type
        self.recipient = None  # Track the recipient for private messages
        master.title("Secure Chat Client")
        
        master.minsize(width=400, height=500)

        # Create a PanedWindow
        self.paned_window = ttk.PanedWindow(master, orient=tk.HORIZONTAL)
        self.paned_window.pack(expand=True, fill='both')

        # Left pane for chat
        self.left_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.left_frame, weight=3)

        # Add a label to display the username and user ID
        self.username_label = tk.Label(self.left_frame, text=f"Username: {self.username} (ID: {self.user_id})", font=("Helvetica", 12))
        self.username_label.pack(side='top', fill='x')

        self.chat_display = scrolledtext.ScrolledText(self.left_frame, state='disabled')
        self.chat_display.pack(expand=True, fill='both')

        self.msg_entry = tk.Entry(self.left_frame)
        self.msg_entry.pack(side='left', expand=True, fill='x')

        self.send_button = tk.Button(self.left_frame, text="Send", command=self.send_message)
        self.send_button.pack(side='right')

        # Bind the Return key to the send_message method
        self.msg_entry.bind('<Return>', self.send_message)

        # Right pane for user list
        self.right_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_frame, weight=1)

        self.user_list_label = tk.Label(self.right_frame, text="Connected Users")
        self.user_list_label.pack()

        self.user_listbox = tk.Listbox(self.right_frame)
        self.user_listbox.pack(expand=True, fill='both')

        # Command buttons
        self.command_frame = ttk.Frame(self.left_frame)
        self.command_frame.pack(side='bottom', fill='x')

        self.private_button = tk.Button(self.command_frame, text="Private", command=self.toggle_message_type)
        self.private_button.pack(side='left')

        self.file_button = tk.Button(self.command_frame, text="File", command=self.send_file_command)
        self.file_button.pack(side='left')

        # Add a "Log Out" button at the top right corner
        self.logout_button = tk.Button(master, text="Log Out", command=self.log_out)
        self.logout_button.pack(side='top', anchor='ne')

        self.websocket = None
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.start_loop, daemon=True).start()

        # Bind the window close event to the cleanup function
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def start_chat_client(self):
        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        asyncio.run_coroutine_threadsafe(self.chat_client(password), self.loop)

    async def chat_client(self, password):
        uri = "wss://localhost:8766"
        cert_file, key_file = generate_user_certificates(self.username, self.user_id, password)
        ssl_context = load_user_ssl_context(self.username, self.user_id, password)

        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                self.websocket = websocket
                await self.send_hello()
                await self.listen_for_messages()
        except Exception as e:
            self.display_message(f"Error: {e}")

    async def send_hello(self):
        global counter
        hello_message = {
            "type": "signed_data",
            "data": {
                "type": "hello",
                "public_key": public_pem,
                "username": self.username,
                "user_id": self.user_id
            },
            "counter": counter,
            "signature": sign_message({"type": "hello", "public_key": public_pem, "username": self.username, "user_id": self.user_id}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(hello_message))

    async def send_chat(self, message):
        global counter
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        chat_message = {
            "type": "signed_data",
            "data": {
                "type": "public_chat",
                "sender": self.username,
                "user_id": self.user_id,
                "message": message,
                "timestamp": timestamp
            },
            "counter": counter,
            "signature": sign_message({"type": "public_chat", "sender": self.username, "user_id": self.user_id, "message": message, "timestamp": timestamp}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(chat_message))

    async def send_private_chat(self, recipient, message):
        global counter
        private_chat_message = {
            "type": "signed_data",
            "data": {
                "type": "private_chat",
                "recipient": recipient,
                "message": message,
                "sender": self.username,
                "user_id": self.user_id
            },
            "counter": counter,
            "signature": sign_message({"type": "private_chat", "recipient": recipient, "message": message, "sender": self.username, "user_id": self.user_id}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(private_chat_message))
        self.display_message(f"[Private] {self.username}: {message}")
        print(f"Sent private message to {recipient}: {message}")  # Debugging statement

    async def send_file_transfer(self, recipient, file_url, file_name):
        global counter
        try:
            file_transfer_message = {
                "type": "signed_data",
                "data": {
                    "type": "file_transfer",
                    "recipient": recipient,
                    "file_url": file_url,
                    "sender": self.username,
                    "file_name": file_name
                },
                "counter": counter,
                "signature": sign_message({"type": "file_transfer", "recipient": recipient, "file_url": file_url, "sender": self.username, "file_name": file_name}, counter)
            }
            counter += 1
            await self.websocket.send(json.dumps(file_transfer_message))
            self.display_message(f"File sent to {recipient}: {file_name}", is_link=True)
        except Exception as e:
            self.display_message(f"Error: {e}")

    async def listen_for_messages(self):
        try:
            async for message in self.websocket:
                data = json.loads(message)
                if data['type'] == 'chat_message':
                    self.display_message(data['message'])
                elif data['type'] == 'user_list':
                    self.update_user_list(data['users'])
                elif data['type'] == 'file_transfer':
                    self.receive_file(data['file_url'], data['sender'], data['file_name'])
        except websockets.ConnectionClosed:
            self.display_message("Connection closed.")
        except Exception as e:
            self.display_message(f"Error: {e}")

    def receive_file(self, file_url, sender, file_name):
        try:
            response = requests.get(file_url)
            response.raise_for_status()
            file_path = filedialog.asksaveasfilename(defaultextension=".bin", initialfile=file_name)
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                self.display_message(f"File received from {sender}: {file_name}", is_link=True)
        except Exception as e:
            self.display_message(f"Error receiving file: {e}")

    def send_message(self, event=None):
        message = sanitize_input(self.msg_entry.get())
        if message:
            if self.message_type == "public":
                asyncio.run_coroutine_threadsafe(self.send_chat(message), self.loop)
            elif self.message_type == "private" and self.recipient:
                asyncio.run_coroutine_threadsafe(self.send_private_chat(self.recipient, message), self.loop)
            self.msg_entry.delete(0, tk.END)

    def toggle_message_type(self):
        if self.message_type == "public":
            self.message_type = "private"
            self.private_button.config(text="Public")
            self.select_recipient()
        else:
            self.message_type = "public"
            self.private_button.config(text="Private")
            self.display_message("Switched to public message mode.")

    def select_recipient(self):
        users = self.user_listbox.get(0, tk.END)
        if not users:
            self.display_message("No other users connected.")
            return

        recipient_selection_window = tk.Toplevel(self.master)
        recipient_selection_window.title("Select Recipient")

        tk.Label(recipient_selection_window, text="Select recipient for private message:").pack(pady=10)

        recipient_var = tk.StringVar(recipient_selection_window)
        recipient_var.set(users[0])  # Set default value

        recipient_dropdown = ttk.Combobox(recipient_selection_window, textvariable=recipient_var, values=users)
        recipient_dropdown.pack(pady=10)

        def set_recipient():
            self.recipient = recipient_var.get()
            self.display_message(f"Switched to private message mode. Recipient: {self.recipient}")
            recipient_selection_window.destroy()

        tk.Button(recipient_selection_window, text="Select", command=set_recipient).pack(pady=10)

    def send_file_command(self):
        recipient = simpledialog.askstring("File Transfer", "Enter recipient username:")
        
        # Check if the recipient is the sender or not in the user list
        if recipient == self.username:
            self.display_message("You cannot send a file to yourself.")
        elif recipient not in self.user_listbox.get(0, tk.END):
            self.display_message("Recipient not found.")
        elif recipient:
            file_path = filedialog.askopenfilename()
            if file_path:
                asyncio.run_coroutine_threadsafe(self.upload_file(file_path, recipient), self.loop)

    async def upload_file(self, file_path, recipient):
        try:
            with open(file_path, 'rb') as f:
                response = requests.post('http://localhost:5001/upload', files={'file': f})
                response.raise_for_status()
                file_url = response.json()['url']
                file_name = os.path.basename(file_path)
                await self.send_file_transfer(recipient, file_url, file_name)
        except FileNotFoundError:
            self.display_message("File not found.")
        except requests.exceptions.RequestException as e:
            self.display_message(f"Error uploading file: {e}")

    def display_message(self, message, is_link=False):
        self.chat_display.configure(state='normal')
        if is_link:
            self.chat_display.insert(tk.END, message + "\n", ('link',))
            self.chat_display.tag_config('link', foreground="blue", underline=True)
            self.chat_display.tag_bind('link', '<Button-1>', lambda e: webbrowser.open(message.split()[-1]))
        else:
            self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user in users:
            if user['username'] != self.username:
                self.user_listbox.insert(tk.END, user['username'])
        self.highlight_recipient()

    def highlight_recipient(self):
        if self.recipient:
            try:
                index = self.user_listbox.get(0, tk.END).index(self.recipient)
                self.user_listbox.selection_set(index)
                self.user_listbox.activate(index)
            except ValueError:
                self.recipient = None

    def log_out(self):
        cleanup(self.username, self.user_id)
        self.master.destroy()

    def on_closing(self):
        cleanup(self.username, self.user_id)
        self.master.destroy()

def sign_message(data, counter):
    message = json.dumps(data) + str(counter)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def get_fingerprint(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_bytes)
    return base64.b64encode(digest.finalize()).decode('utf-8')

def signal_handler(signal, frame):
    cleanup(username, user_id)
    os._exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    username = sanitize_input(simpledialog.askstring("Username", "Enter your username:"))
    if username:
        user_id = str(uuid.uuid4())
        root.deiconify()  # Show the root window
        root.geometry("800x400")
        chat_gui = ChatGUI(root, username, user_id)
        signal.signal(signal.SIGINT, signal_handler)
        chat_gui.start_chat_client()  # Start the chat client
        root.mainloop()
    else:
        print("Username is required to start the chat.")