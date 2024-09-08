import asyncio
import websockets
import json

clients = {}

async def handle_client(websocket, path):
    async for message in websocket:
        data = json.loads(message)
        if data['data']['type'] == 'hello':
            public_key = data['data']['public_key']
            clients[websocket] = public_key
            await broadcast_client_update()
        elif data['data']['type'] == 'chat':
            await relay_message(data)

async def broadcast_client_update():
    client_update = {
        "type": "client_update",
        "clients": list(clients.values())
    }
    await asyncio.wait([client.send(json.dumps(client_update)) for client in clients])

async def relay_message(data):
    for client in clients:
        await client.send(json.dumps(data))

start_server = websockets.serve(handle_client, "localhost", 9002)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()