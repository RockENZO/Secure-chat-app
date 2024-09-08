import asyncio
import websockets
import json
from common.encryption import generate_rsa_keypair, encrypt_message, decrypt_message

async def send_hello(websocket, public_key):
    hello_message = {
        "data": {
            "type": "hello",
            "public_key": public_key
        }
    }
    await websocket.send(json.dumps(hello_message))

async def send_chat(websocket, message, recipient_public_key):
    encrypted_message, iv, encrypted_aes_key = encrypt_message(message, recipient_public_key)
    chat_message = {
        "data": {
            "type": "chat",
            "destination_servers": ["localhost:9002"],
            "iv": iv,
            "symm_keys": [encrypted_aes_key],
            "chat": encrypted_message
        }
    }
    await websocket.send(json.dumps(chat_message))

async def receive_message(websocket, private_key):
    async for message in websocket:
        data = json.loads(message)
        if data['data']['type'] == 'chat':
            decrypted_message = decrypt_message(data, private_key)
            print(f"Received message: {decrypted_message}")

async def main():
    private_key, public_key = generate_rsa_keypair()
    async with websockets.connect("ws://localhost:9002") as websocket:
        await send_hello(websocket, public_key)
        await send_chat(websocket, "Hello, World!", public_key)
        await receive_message(websocket, private_key)

asyncio.get_event_loop().run_until_complete(main())