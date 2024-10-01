import os
import subprocess
import tkinter as tk
import asyncio
import websockets
import threading
import ssl
import json
import base64
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from tkinter import scrolledtext, ttk, simpledialog, filedialog
import webbrowser
import signal
import requests
import re
# Generate SSL/TLS certificates for the user
def generate_user_certificates(username, user_id):
    cert_file = f"{username}_{user_id}_cert.pem"
    key_file = f"{username}_{user_id}_key.pem"
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_file, "-out", cert_file, "-days", "365", "-nodes",
            f"-subj", f"/CN={username}/UID={user_id}"
        ])
        print(f"SSL/TLS certificates generated for {username} with ID {user_id}.")
    return cert_file, key_file

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
        self.loop.run_until_complete(self.chat_client())

    async def chat_client(self):
        uri = "wss://localhost:8766"
        cert_file, key_file = generate_user_certificates(self.username, self.user_id)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
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
        self.display_message(f"Your Private message:\" {message} \"is sent to {recipient}")  # Display the message on sender's GUI
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
                    "file_name": file_name,
                    "sender": self.username,
                    "user_id": self.user_id
                },
                "counter": counter,
                "signature": sign_message({
                    "type": "file_transfer",
                    "recipient": recipient,
                    "file_url": file_url,
                    "file_name": file_name,
                    "sender": self.username,
                    "user_id": self.user_id
                }, counter)
            }

            counter += 1

            # Send the message via WebSocket
            await self.websocket.send(json.dumps(file_transfer_message))

            self.display_message(f"File sent to {recipient}: {file_url}")
            
        except Exception as e:
            self.display_message(f"Failed to send file to {recipient}: {e}")

    async def listen_for_messages(self):
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                print(f"Received message: {data}") 
                if data['type'] == 'chat_message':
                    self.display_message(data['message'])
                elif data['type'] == 'user_list':
                    self.update_user_list(data['users'])
                elif data['type'] == 'file_transfer':
                    self.receive_file(data['file_url'], data['sender'], data['file_name'])
        except websockets.ConnectionClosed:
            self.display_message("Connection to the server closed")
        except Exception as e:
            self.display_message(f"Error receiving message: {e}")
            
    def receive_file(self, file_url, sender, file_name):
        try:
            # get extension of the file
            file_extension = file_name.split('.')[-1]
            
            file_path = filedialog.asksaveasfilename(defaultextension = file_extension, initialfile = "received_file." + file_extension)

            if file_path:
                # Download the file from the provided URL
                response = requests.get(file_url)

                if response.status_code == 200:
                    # Save the downloaded file to the specified path
                    with open(file_path, 'wb') as file:
                        file.write(response.content)

                    self.display_message(f"File received from {sender} and saved as {file_path}")
                else:
                    self.display_message(f"Failed to download file from {file_url}")
            else:
                self.display_message("File save operation was canceled.")

        except Exception as e:
            self.display_message(f"Error receiving file from {sender}: {e}")

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
            self.recipient = sanitize_input(simpledialog.askstring("Private Message", "Enter recipient username:"))
            if self.recipient:
                self.message_type = "private"
                self.private_button.config(text="Public")
                self.username_label.config(text=f"Username: {self.username} (ID: {self.user_id}) (Private to: {self.recipient})")
                self.highlight_recipient()
        else:
            self.message_type = "public"
            self.recipient = None
            self.private_button.config(text="Private")
            self.username_label.config(text=f"Username: {self.username} (ID: {self.user_id})")
            self.user_listbox.selection_clear(0, tk.END)

    def send_file_command(self):
        recipient = simpledialog.askstring("File Transfer", "Enter recipient username:")
        if recipient:
            file_path = filedialog.askopenfilename()
            if file_path:
                file_url = self.upload_file(file_path)
                if file_url:
                    file_name = os.path.basename(file_path)
                    asyncio.run_coroutine_threadsafe(self.send_file_transfer(recipient, file_url, file_name), self.loop)

    def upload_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                # Upload the file to the server
                response = requests.post('http://localhost:5001/upload', files={'file': file})

                if response.status_code == 200:
                    try:
                        file_url = response.json().get('url')
                        if file_url:
                            self.display_message(f"File uploaded: {file_path}, available at: {file_url}")
                            return file_url
                        else:
                            # Handle the unexpected response structure
                            self.display_message(f"Unexpected response structure: {response.json()}")
                            return None
                    # Handle JSON parsing errors
                    except requests.exceptions.JSONDecodeError:
                        self.display_message("Failed to parse JSON response")
                        return None
                else:
                    try:
                        # Try to get the error message from the response JSON
                        error_message = response.json().get('error', 'Unknown error')
                        self.display_message(f"Failed to upload file: {error_message}")
                    except requests.exceptions.JSONDecodeError:
                        # If the response isn't JSON, just display the HTTP status code
                        self.display_message(f"Failed to upload file: HTTP {response.status_code}")
                    return None

        except FileNotFoundError:
            self.display_message(f"File not found: {file_path}")
            return None

        except requests.exceptions.RequestException as e:
            # Catch network-related errors
            self.display_message(f"Request failed: {e}")
            return None

    def display_message(self, message, is_link=False):
        self.chat_display.configure(state='normal')
        if is_link:
            self.chat_display.insert(tk.END, message + '\n', ('link',))
            self.chat_display.tag_config('link', foreground='blue', underline=True)
            self.chat_display.tag_bind('link', '<Button-1>', lambda e: webbrowser.open(message.split()[-1]))
        else:
            self.chat_display.insert(tk.END, message + '\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def update_user_list(self, users):
        self.user_listbox.delete(0, tk.END)
        for user in users:
            self.user_listbox.insert(tk.END, user)
        self.highlight_recipient()

    def highlight_recipient(self):
        if self.recipient:
            for i in range(self.user_listbox.size()):
                if self.user_listbox.get(i) == self.recipient:
                    self.user_listbox.selection_set(i)
                    self.user_listbox.see(i)
                    break

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
        root.mainloop()
    else:
        print("Username is required to start the chat.")