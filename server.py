import asyncio
import websockets
import ssl

# Dictionary to store the mapping of clients to usernames
clients = {}

async def handler(websocket, path):
    username = f"User{len(clients) + 1}"
    clients[websocket] = username

    join_message = f"{username} has joined the chat!"
    print(join_message)
    await notify_all(join_message)

    try:
        while True:
            message = await websocket.recv()
            chat_message = f"{username}: {message}"
            print(chat_message)
            await notify_all(chat_message)

    except websockets.ConnectionClosedError:
        print(f"{username} disconnected unexpectedly.")
        await notify_all(f"{username} has left the chat")

    finally:
        del clients[websocket]

async def notify_all(message):
    disconnected_clients = []
    for client in clients:
        try:
            await client.send(message)
        except websockets.ConnectionClosedError:
            disconnected_clients.append(client)

    # Clean up disconnected clients
    for client in disconnected_clients:
        del clients[client]

# SSL context to secure the WebSocket server
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Start the WebSocket server on wss://localhost:8765 with increased ping interval and timeout
start_server = websockets.serve(
    handler, 
    "localhost", 
    8765, 
    ssl=ssl_context, 
    ping_interval=20,  # Increase ping interval (default is 20s)
    ping_timeout=20    # Increase ping timeout (default is 20s)
)

# Run the server event loop
asyncio.get_event_loop().run_until_complete(start_server)
print("Server started, listening on wss://localhost:8765")
asyncio.get_event_loop().run_forever()
