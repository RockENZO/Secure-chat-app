import ssl
import websockets
import asyncio
import json
import base64
from encryption import generate_rsa_keypair, encrypt_message, decrypt_message
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA key pair
private_key, public_key = generate_rsa_keypair()

# Serialize public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Counter for message signing
counter = 0

async def chat_client():
    uri = "wss://localhost:8766"  # Changed port number
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            print("Connected to the chat server")

            # Send hello message
            await send_hello(websocket)

            # Start listening for messages from the server in a separate task
            asyncio.create_task(listen_for_messages(websocket))

            while True:
                message = input("You: ")
                await send_chat(websocket, message)

    except Exception as e:
        print(f"Error: {e}")

async def send_hello(websocket):
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
    await websocket.send(json.dumps(hello_message))

async def send_chat(websocket, message):
    global counter
    chat_message = {
        "type": "signed_data",
        "data": {
            "type": "public_chat",
            "sender": get_fingerprint(public_key),
            "message": message
        },
        "counter": counter,
        "signature": sign_message({"type": "public_chat", "sender": get_fingerprint(public_key), "message": message}, counter)
    }
    counter += 1
    await websocket.send(json.dumps(chat_message))

async def listen_for_messages(websocket):
    try:
        while True:
            message = await websocket.recv()
            print(message)
    except websockets.ConnectionClosed:
        print("Connection to the server closed")

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

asyncio.get_event_loop().run_until_complete(chat_client())