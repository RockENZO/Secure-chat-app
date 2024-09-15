import tkinter as tk
import asyncio
import websockets
import threading
import ssl
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading

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
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.message_type = "public"  # Track the message type
        self.recipient = None  # Track the recipient for private messages
        master.title("Secure Chat Client")

        self.token = None

        # Create login frame
        self.login_frame = ttk.Frame(master)
        self.login_frame.pack(expand=True, fill='both')

        self.username_label = ttk.Label(self.login_frame, text="Username")
        self.username_label.pack()
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack()

        self.password_label = ttk.Label(self.login_frame, text="Password")
        self.password_label.pack()
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack()

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.pack()

        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.register)
        self.register_button.pack()

        # Create chat frame
        self.chat_frame = ttk.Frame(master)

        self.paned_window = ttk.PanedWindow(self.chat_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(expand=True, fill='both')

        self.left_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.left_frame, weight=3)

        # Add a label to display the username
        self.username_label = tk.Label(self.left_frame, text=f"Username: {self.username}", font=("Helvetica", 12))
        self.username_label.pack(side='top', fill='x')

        self.chat_display = scrolledtext.ScrolledText(self.left_frame, state='disabled')
        self.chat_display.pack(expand=True, fill='both')

        self.msg_entry = tk.Entry(self.left_frame)
        self.msg_entry.pack(side='left', expand=True, fill='x')

        self.send_button = tk.Button(self.left_frame, text="Send", command=self.send_message)
        self.send_button.pack(side='right')

        self.right_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_frame, weight=1)

        self.user_list_label = tk.Label(self.right_frame, text="Connected Users")
        self.user_list_label.pack()

        self.user_listbox = tk.Listbox(self.right_frame)
        self.user_listbox.pack(expand=True, fill='both')

        self.websocket = None
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.start_loop, daemon=True).start()

    def start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def connect(self):
        asyncio.run_coroutine_threadsafe(self.chat_client(), self.loop)

    async def chat_client(self):
        uri = "wss://localhost:8766"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

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
                "username": self.username
            },
            "counter": counter,
            "signature": sign_message({"type": "hello", "public_key": public_pem}, counter),
            "token": self.token
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
                "message": message,
                "timestamp": timestamp
            },
            "counter": counter,
            "signature": sign_message({"type": "public_chat", "sender": self.username, "message": message, "timestamp": timestamp}, counter)
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
                "sender": self.username
            },
            "counter": counter,
            "signature": sign_message({"type": "private_chat", "recipient": recipient, "message": message, "sender": self.username}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(private_chat_message))
        print(f"Sent private message to {recipient}: {message}")  # Debugging statement

    async def send_file_transfer(self, recipient, file_content):
        global counter
        file_transfer_message = {
            "type": "signed_data",
            "data": {
                "type": "file_transfer",
                "recipient": recipient,
                "file_content": file_content,
                "sender": self.username
            },
            "counter": counter,
            "signature": sign_message({"type": "file_transfer", "recipient": recipient, "file_content": file_content, "sender": self.username}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(file_transfer_message))

    async def listen_for_messages(self):
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                if data['type'] == 'chat_message':
                    self.display_message(data['message'])
                elif data['type'] == 'user_list':
                    self.update_user_list(data['users'])
        except websockets.ConnectionClosed:
            self.display_message("Connection to the server closed")

    def send_message(self):
        message = self.msg_entry.get()
        if message:
            if self.message_type == "public":
                asyncio.run_coroutine_threadsafe(self.send_chat(message), self.loop)
            elif self.message_type == "private" and self.recipient:
                asyncio.run_coroutine_threadsafe(self.send_private_chat(self.recipient, message), self.loop)
            self.msg_entry.delete(0, tk.END)

    def toggle_message_type(self):
        if self.message_type == "public":
            self.recipient = simpledialog.askstring("Private Message", "Enter recipient username:")
            if self.recipient:
                self.message_type = "private"
                self.private_button.config(text="Public")
        else:
            self.message_type = "public"
            self.recipient = None
            self.private_button.config(text="Private")

    def send_file_command(self):
        recipient = simpledialog.askstring("File Transfer", "Enter recipient username:")
        file_content = self.msg_entry.get()
        if recipient and file_content:
            asyncio.run_coroutine_threadsafe(self.send_file_transfer(recipient, file_content), self.loop)
            self.msg_entry.delete(0, tk.END)

    def display_message(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message + '\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user in users:
            self.user_listbox.insert(tk.END, user)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        print(f"Attempting to login with username: {username}")
        asyncio.run_coroutine_threadsafe(self.authenticate('login', username, password), self.loop)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        print(f"Attempting to register with username: {username}")
        asyncio.run_coroutine_threadsafe(self.authenticate('register', username, password), self.loop)

    async def authenticate(self, action, username, password):
        uri = "wss://localhost:8766"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                auth_message = {
                    "type": "auth",
                    "action": action,
                    "username": username,
                    "password": password
                }
                await websocket.send(json.dumps(auth_message))
                print(f"Sent {action} request for username: {username}")
                response = await websocket.recv()
                data = json.loads(response)
                print(f"Received response: {data}")
                if data['type'] == 'success':
                    if action == 'login':
                        self.token = data['token']
                        print("Login successful, transitioning to chat frame")
                        self.master.after(0, self.show_chat_frame)
                        self.connect()
                    else:
                        self.display_message("Registration successful. Please log in.")
                else:
                    self.display_message(data['message'])
        except Exception as e:
            self.display_message(f"Error: {e}")

    def show_chat_frame(self):
        print("Transitioning to chat frame")
        self.login_frame.pack_forget()
        self.chat_frame.pack(expand=True, fill='both')

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

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    username = simpledialog.askstring("Username", "Enter your username:")
    if username:
        root.deiconify()  # Show the root window
        chat_gui = ChatGUI(root, username)
        root.mainloop()
    else:
        print("Username is required to start the chat.")