import os
import subprocess
import asyncio
import websockets
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import ssl
import signal
import secrets

connected_clients = {}
tokens = {}

# Generate SSL/TLS certificates if they don't exist
def generate_ssl_certificates():
    cert_file = "server.crt"
    key_file = "server.key"
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_file, "-out", cert_file, "-days", "365", "-nodes",
            "-subj", "/CN=localhost"
        ])
        print("SSL/TLS certificates generated.")

# Cleanup function to delete server certificate and key files
def cleanup():
    cert_file = "server.crt"
    key_file = "server.key"
    if os.path.exists(cert_file):
        os.remove(cert_file)
    if os.path.exists(key_file):
        os.remove(key_file)
    print("SSL/TLS certificates removed.")

# Call the function to generate SSL/TLS certificates
generate_ssl_certificates()

def generate_token():
    return secrets.token_hex(16)

async def handle_client(websocket, path):
    global connected_clients
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'auth':
                username = data['username']
                user_id = data['user_id']
                token = generate_token()
                tokens[token] = {'username': username, 'user_id': user_id}
                await websocket.send(json.dumps({'type': 'auth_response', 'token': token}))
            elif data['type'] == 'signed_data':
                token = data.get('token')
                if token not in tokens:
                    await websocket.send(json.dumps({'type': 'error', 'message': 'Invalid token'}))
                    continue
                if data['data']['type'] == 'hello':
                    username = data['data']['username']
                    user_id = data['data']['user_id']
                    public_key_pem = data['data']['public_key']
                    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                    fingerprint = get_fingerprint(public_key)
                    connected_clients[fingerprint] = {
                        'websocket': websocket,
                        'username': username,
                        'user_id': user_id,
                        'public_key': public_key
                    }
                    await broadcast_user_list()
                elif data['data']['type'] == 'public_chat':
                    await broadcast_message(data['data']['message'], data['data']['sender'])
                elif data['data']['type'] == 'private_chat':
                    recipient = data['data']['recipient']
                    message = data['data']['message']
                    sender = data['data']['sender']
                    await send_private_message(recipient, message, sender)
                elif data['data']['type'] == 'file_transfer':
                    recipient = data['data']['recipient']
                    file_content = data['data']['file_content']
                    sender = data['data']['sender']
                    await send_file_transfer(recipient, file_content, sender)
                elif data['data']['type'] == 'list_members':
                    await send_user_list(websocket)
    except websockets.ConnectionClosed:
        fingerprint = None
        for fp, client in connected_clients.items():
            if client['websocket'] == websocket:
                fingerprint = fp
                break
        if fingerprint:
            del connected_clients[fingerprint]
            await broadcast_user_list()

async def broadcast_message(message, sender):
    for client in connected_clients.values():
        await client['websocket'].send(json.dumps({
            'type': 'chat_message',
            'message': f"[Public] {sender}: {message}"
        }))

async def send_private_message(recipient, message, sender):
    recipient_fingerprint = None
    for fp, client in connected_clients.items():
        if client['username'] == recipient:
            recipient_fingerprint = fp
            break

    if recipient_fingerprint and recipient_fingerprint in connected_clients:
        await connected_clients[recipient_fingerprint]['websocket'].send(json.dumps({
            'type': 'chat_message',
            'message': f"[Private] {sender}: {message}"
        }))
        print(f"{sender} sent a private message to {recipient}")  # Generic log message
    else:
        print(f"Recipient {recipient} not found")  # Debugging statement

async def send_file_transfer(recipient, file_content, sender):
    recipient_fingerprint = None
    for fp, client in connected_clients.items():
        if client['username'] == recipient:
            recipient_fingerprint = fp
            break

    if recipient_fingerprint and recipient_fingerprint in connected_clients:
        await connected_clients[recipient_fingerprint]['websocket'].send(json.dumps({
            'type': 'file_transfer',
            'file_content': file_content,
            'sender': sender
        }))

async def send_user_list(websocket):
    users = [{"username": client['username'], "user_id": client['user_id']} for client in connected_clients.values()]
    await websocket.send(json.dumps({
        'type': 'user_list',
        'users': users
    }))

async def broadcast_user_list():
    users = [{"username": client['username'], "user_id": client['user_id']} for client in connected_clients.values()]
    for client in connected_clients.values():
        await client['websocket'].send(json.dumps({
            'type': 'user_list',
            'users': users
        }))

def get_fingerprint(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_bytes)
    return base64.b64encode(digest.finalize()).decode('utf-8')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

start_server = websockets.serve(handle_client, "localhost", 8766, ssl=ssl_context)

loop = asyncio.get_event_loop()

# Register signal handlers for graceful shutdown
def signal_handler(signal, frame):
    loop.stop()
    cleanup()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

try:
    loop.run_until_complete(start_server)
    loop.run_forever()
finally:
    cleanup()