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
        print("ConnectionClosedError caught")
        await handle_disconnect(websocket)
    except Exception as e:
        print(f"Unexpected error: {e}")


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

async def handle_public_chat(websocket, data):
    if not verify_message(data, websocket):
        print("Invalid message signature")
        return
    username = clients[websocket]
    chat_message = f"{username} [{data['data']['timestamp']}]: {data['data']['message']}"  # Display timestamp
    print(chat_message)
    await notify_all(chat_message)

async def handle_disconnect(websocket):
    if websocket in clients:
        username = clients[websocket]
        print(f"{username} disconnected unexpectedly.")
        await notify_all(f"{username} has left the chat")
        del clients[websocket]
        del public_keys[websocket]
        del counters[websocket]
    else:
        print("Client was not found in the list")

async def notify_all(message):
    disconnected_clients = []
    for client in clients:
        try:
            await client.send(message)
        except websockets.ConnectionClosedError:
            disconnected_clients.append(client)
    for client in disconnected_clients:
        await handle_disconnect(client)

def verify_message(data, websocket):
    message = json.dumps(data['data']) + str(data['counter'])
    signature = base64.b64decode(data['signature'])
    public_key = public_keys[websocket]
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
        print(f"Verification failed: {e}")
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
