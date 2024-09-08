import ssl
import websockets
import asyncio

async def chat_client():
    # Define the WebSocket URI
    uri = "wss://localhost:8765"

    # Create an SSL context to ignore certificate verification (since we are using a self-signed certificate)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False  # Disable hostname checking for self-signed cert
    ssl_context.verify_mode = ssl.CERT_NONE  # Disable certificate verification for self-signed cert

    try:
        # Establish connection to the server using WebSocket with SSL
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            print("Connected to the chat server")

            # Start listening for messages from the server in a separate task
            asyncio.create_task(listen_for_messages(websocket))

            while True:
                # Take user input for the message to send
                message = input("You: ")

                # Send the message to the server
                await websocket.send(message)

    except Exception as e:
        print(f"Error: {e}")

# Function to listen for messages from the server
async def listen_for_messages(websocket):
    try:
        while True:
            # Receive and print messages from the server
            message = await websocket.recv()
            print(message)
    except websockets.ConnectionClosed:
        print("Connection to the server closed")

# Run the WebSocket client
asyncio.get_event_loop().run_until_complete(chat_client())
