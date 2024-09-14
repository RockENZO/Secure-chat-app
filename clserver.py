import asyncio
import websockets
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import ssl

connected_clients = {}

async def handle_client(websocket, path):
    global connected_clients
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'signed_data':
                if data['data']['type'] == 'hello':
                    username = data['data']['username']
                    public_key_pem = data['data']['public_key']
                    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                    fingerprint = get_fingerprint(public_key)
                    connected_clients[fingerprint] = {
                        'websocket': websocket,
                        'username': username,
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
            'message': f"{sender}: {message}"
        }))

async def send_private_message(recipient, message, sender):
    if recipient in connected_clients:
        await connected_clients[recipient]['websocket'].send(json.dumps({
            'type': 'chat_message',
            'message': f"Private from {sender}: {message}"
        }))

async def send_file_transfer(recipient, file_content, sender):
    if recipient in connected_clients:
        await connected_clients[recipient]['websocket'].send(json.dumps({
            'type': 'file_transfer',
            'file_content': file_content,
            'sender': sender
        }))

async def send_user_list(websocket):
    users = [client['username'] for client in connected_clients.values()]
    await websocket.send(json.dumps({
        'type': 'user_list',
        'users': users
    }))

async def broadcast_user_list():
    users = [client['username'] for client in connected_clients.values()]
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

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()