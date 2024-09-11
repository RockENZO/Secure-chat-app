import ssl
import websockets
import asyncio
import json
import base64
from datetime import datetime
from encryption import generate_rsa_keypair, encrypt_message, decrypt_message
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import scrolledtext
import threading

# Generate RSA key pair
private_key, public_key = generate_rsa_keypair()

# Serialize public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Counter for message signing
counter = 0

class ChatGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure Chat Client")

        self.chat_display = scrolledtext.ScrolledText(master, state='disabled')
        self.chat_display.pack(expand=True, fill='both')

        self.msg_entry = tk.Entry(master)
        self.msg_entry.pack(side='left', expand=True, fill='x')

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(side='right')

        self.websocket = None
        self.connect()

    def connect(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.start_loop, daemon=True).start()

    def start_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.chat_client())

    async def chat_client(self):
        uri = "wss://localhost:8766"
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                self.websocket = websocket
                self.display_message("Connected to the chat server")

                # Send hello message
                await self.send_hello()

                # Start listening for messages from the server
                await self.listen_for_messages()

        except Exception as e:
            self.display_message(f"Error: {e}")

    async def send_hello(self):
        global counter
        hello_message = {
            "type": "signed_data",
            "data": {
                "type": "hello",
                "public_key": public_pem
            },
            "counter": counter,
            "signature": sign_message({"type": "hello", "public_key": public_pem}, counter)
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
                "sender": get_fingerprint(public_key),
                "message": message,
                "timestamp": timestamp
            },
            "counter": counter,
            "signature": sign_message({"type": "public_chat", "sender": get_fingerprint(public_key), "message": message, "timestamp": timestamp}, counter)
        }
        counter += 1
        await self.websocket.send(json.dumps(chat_message))

    async def listen_for_messages(self):
        try:
            while True:
                message = await self.websocket.recv()
                self.display_message(message)
        except websockets.ConnectionClosed:
            self.display_message("Connection to the server closed")

    def send_message(self):
        message = self.msg_entry.get()
        if message:
            asyncio.run_coroutine_threadsafe(self.send_chat(message), self.loop)
            self.msg_entry.delete(0, tk.END)

    def display_message(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message + '\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

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
    chat_gui = ChatGUI(root)
    root.mainloop()