import asyncio
import websockets
import ssl
import json
import base64
from encryption import generate_rsa_keypair, encrypt_message, decrypt_message
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

clients = {}
public_keys = {}
counters = {}

async def handler(websocket, path):
    try:
        async for message in websocket:
            data = json.loads(message)
            if data['type'] == 'signed_data':
                if data['data']['type'] == 'hello':
                    await handle_hello(websocket, data)
                elif data['data']['type'] == 'public_chat':
                    await handle_public_chat(websocket, data)
    except websockets.ConnectionClosedError:
        print(f"Connection closed for {clients.get(websocket, 'Unknown User')}")
    except Exception as e:
        print(f"Unexpected error for {clients.get(websocket, 'Unknown User')}: {e}")
    finally:
        await handle_disconnect(websocket)

async def handle_hello(websocket, data):
    public_key_pem = data['data']['public_key']
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    public_keys[websocket] = public_key
    counters[websocket] = data['counter']
    username = f"User{len(clients) + 1}"
    clients[websocket] = username
    join_message = f"{username} has joined the chat!"
    print(join_message)
    await notify_all(join_message)
    await broadcast_user_list()

async def handle_public_chat(websocket, data):
    if not verify_message(data, websocket):
        print("Invalid message signature")
        return
    username = clients[websocket]
    chat_message = f"{username} [{data['data']['timestamp']}]: {data['data']['message']}"
    print(chat_message)
    await notify_all(chat_message)

async def handle_disconnect(websocket):
    if websocket in clients:
        username = clients[websocket]
        leave_message = f"{username} has left the chat"
        print(leave_message)
        del clients[websocket]
        del public_keys[websocket]
        del counters[websocket]
        await notify_all(leave_message)
        await broadcast_user_list()

async def notify_all(message):
    if clients:
        websockets_to_remove = []
        for client_websocket in clients:
            try:
                await client_websocket.send(json.dumps({"type": "chat_message", "message": message}))
            except websockets.ConnectionClosed:
                websockets_to_remove.append(client_websocket)
        
        for websocket in websockets_to_remove:
            await handle_disconnect(websocket)

async def broadcast_user_list():
    user_list = list(clients.values())
    if clients:
        for client_websocket in clients:
            try:
                await client_websocket.send(json.dumps({"type": "user_list", "users": user_list}))
            except websockets.ConnectionClosed:
                pass  # We'll handle disconnections in the main loop

def verify_message(data, websocket):
    message = json.dumps(data['data']) + str(data['counter'])
    signature = base64.b64decode(data['signature'])
    public_key = public_keys.get(websocket)
    if not public_key:
        print(f"Public key not found for {clients.get(websocket, 'Unknown User')}")
        return False
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        if data['counter'] > counters[websocket]:
            counters[websocket] = data['counter']
            return True
    except Exception as e:
        print(f"Verification failed for {clients.get(websocket, 'Unknown User')}: {e}")
    return False

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

start_server = websockets.serve(
    handler,
    "localhost",
    8766,
    ssl=ssl_context,
    ping_interval=20,
    ping_timeout=20
)

asyncio.get_event_loop().run_until_complete(start_server)
print("Server started, listening on wss://localhost:8766")
asyncio.get_event_loop().run_forever()