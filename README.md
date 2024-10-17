# OLAF/Neighbourhood protocol modified

## Group 
- Ge Wang | a1880714
- Yong Yue Beh | a1843874
- Liew Yi Hui | a1907230

## Setting up virtual environment
```bash
python -m venv .venv
```
To activate the venv, use the command:
```bash
source .venv/bin/activate
```

## Dependencies
asttokens==2.4.1
bcrypt==4.2.0
bidict==0.23.1
blinker==1.8.2
canonicaljson==2.0.0
certifi==2024.8.30
charset-normalizer==3.3.2
click==8.1.7
comm==0.2.2
command-not-found==0.3
cryptography==3.4.8
dbus-python==1.2.18
debugpy==1.8.5
decorator==5.1.1
distlib==0.3.4
distro==1.7.0
distro-info===1.1build1
exceptiongroup==1.2.2
executing==2.1.0
filelock==3.6.0
Flask==3.0.3
Flask-Bcrypt==1.0.1
Flask-Cors==5.0.0
Flask-SocketIO==5.4.1
gyp==0.1
h11==0.14.0
httplib2==0.20.2
idna==3.10
importlib-metadata==4.6.4
ipykernel==6.29.5
ipython==8.27.0
itsdangerous==2.2.0
jedi==0.19.1
jeepney==0.7.1
Jinja2==3.1.4
jupyter_client==8.6.2
jupyter_core==5.7.2
keyring==23.5.0
launchpadlib==1.10.16
lazr.restfulclient==0.14.4
lazr.uri==1.0.6
MarkupSafe==2.1.5
matplotlib-inline==0.1.7
more-itertools==8.10.0
nest-asyncio==1.6.0
netifaces==0.11.0
oauthlib==3.2.0
packaging==24.1
parso==0.8.4
pexpect==4.9.0
platformdirs==4.3.2
prompt_toolkit==3.0.47
psutil==6.0.0
ptyprocess==0.7.0
pure_eval==0.2.3
pycryptodome==3.21.0
Pygments==2.11.2
PyGObject==3.42.1
PyJWT==2.3.0
pyparsing==2.4.7
python-apt==2.4.0+ubuntu1
python-dateutil==2.9.0.post0
python-engineio==4.9.1
python-socketio==5.11.4
PyYAML==5.4.1
pyzmq==26.2.0
requests==2.32.3
SecretStorage==3.3.1
simple-websocket==1.0.0
six==1.16.0
stack-data==0.6.3
systemd-python==234
tk==0.1.0
tornado==6.4.1
traitlets==5.14.3
typing_extensions==4.12.2
ubuntu-advantage-tools==8001
ufw==0.36.1
unattended-upgrades==0.1
urllib3==2.2.3
virtualenv==20.13.0+ds
wadllib==1.3.6
wcwidth==0.2.13
websockets==13.0.1
Werkzeug==3.0.4
wsproto==1.2.0
zipp==1.0.0

## Installation

First, install the required dependencies using the following command:

```bash
pip install -r requirements.txt
```

- And then for the tkinter GUI:
  - For mac:
```bash
brew install tcl-tk
```

  - For win/linux:
```bash
sudo apt-get install python3-tk
```


## Running the Application
To start the WebSocket server, run:
```bash
python server.py
```

To run the client and connect to the WebSocket server, use:
```bash
python client.py
```

## Definitions
- **User** A user has a key pair. Each user connects to one server at a time.
- **Server** A server receives messages from clients and relays them towards the destination.
- **Neighbourhood** Servers organise themselves in a meshed network called a neighborhood. Each server in a neighbourhood is aware of and connects to all other servers
- **Fingerprint** A fingerprint is the unique identification of a user. It is obtained by taking SHA-256(exported RSA public key)

## Main design principles
This protocol specification was obtained by taking parts of the original OLAF protocol combined with the neighbourhood protocol. The network structure resembles the original neighbourhood, while the messages and roles of the servers are similar to OLAF.

## Network Topology
Client-to-client messages travel in the following path:
```
Client (Sender)
  |
  |  Message sent directly
  V  
Server (Owner of the sender)
  |
  |  Message routed to the correct server
  V  
Server (Owner of the receiver)
  |
  |  Message flooded to all receiving clients
  V  
Client (Receiver)
```

If a server "owns" a client, that just means that the client is connected to that server. (Since clients only connect to one server at a time)

The transport layer of this protocol uses Websockets (RFC 6455)

## Protocol defined messages
All messages are sent as UTF-8 JSON objects. 

### Sent by client
Messages include a counter and are signed to prevent replay attacks.

All below messages with `data` follow the below structure:
```JSON
{
    "type": "signed_data",
    "data": {  },
    "counter": 12345,
    "signature": "<Base64 signature of data + counter>"
}
```
`counter` is a monotonically increasing integer. All handlers of a message should track the last counter value sent by a client and reject it if the current value is not greater than the last value. This defeats replay attacks.
The hash used for `signature` follows the SHA-256 algorithm.

#### Hello
This message is sent when first connecting to a server to establish your public key.
```JSON
{
    "data": {
        "type": "hello",
        "public_key": "<Exported RSA public key>"
    }
}
```

### Chat
Sent when a user wants to send a chat message to another user[s]. Chat messages are end-to-end encrypted.

```JSON
{
    "data": {
        "type": "chat",
        "destination_servers": [
            "<Address of each recipient's destination server>",
        ],
        "iv": "<Base64 encoded AES initialisation vector>",
        "symm_keys": [
            "<Base64 encoded AES key, encrypted with each recipient's public RSA key>",
        ],
        "chat": "<Base64 encoded AES encrypted segment>"
    }
}

{
    "chat": {
        "participants": [
            "<Base64 encoded list of fingerprints of participants, starting with sender>",
        ],
        "message": "<Plaintext message>"
    }
}
```

Group chats are defined similar to how group emails work. Simply send a message to all recipients with multiple `participants`. The `symm_keys` field is an array which lists the AES key for the message encrypted for each recipient using their respective asymmetric key. Each of the `destination_servers`, `symm_keys`, and `participants` are in the same order, except for the sender, which is only included in the `participants` list.

### Public chat
Public chats are not encrypted at all and are broadcasted as plaintext.

```JSON
{
    "data": {
        "type": "public_chat",
        "sender": "<Base64 encoded fingerprint of sender>",
        "message": "<Plaintext message>"
    }
}
```

### Client list
To retrieve a list of all currently connected clients on all servers. Your server will send a JSON response. This does not follow the `data` structure.

```JSON
{
    "type": "client_list_request",
}
```
Server response:
```JSON
{
    "type": "client_list",
    "servers": [
        {
            "address": "<Address of server>",
            "clients": [
                "<Exported RSA public key of client>",
            ]
        },
    ]
}
```

### Sent by server
#### Client update
A server will know when a client disconnects as the socket connection will drop off. 

When one of the following things happens, a server should send a `client_update` message to all other servers in the neighbourhood so that they can update their internal state.
1. A client sends `hello`
2. A client disconnects

You don't need to send an update for clients who disconnected before sending `hello`.

The `client_update` advertises all currently connected users on a particular server.
```JSON
{
    "type": "client_update",
    "clients": [
        "<Exported RSA public key of client>",
    ]
}
```

#### Client update request
When a server comes online, it will have no initial knowledge of clients connected elsewhere, so it needs to request a `client_update` from all other servers in the neighbourhood.

```JSON
{
    "type": "client_update_request"
}
```
All other servers respond by sending `client_update`

## File transfers
File transfers are performed over an HTTP[S] API.

### Upload file
Uplaod a file in the same format as an HTTP form.
```
"<server>/api/upload" {
    METHOD: POST
    body: file
}
```
The server makes no guarantees that it will accept your file or retain it for any given length of time. It can also reject the file based on an arbitrary file size limit. An appropriate `413` error can be returned for this case.

A successful file upload will result in the following response:
```
response {
    body: {
        file_url: "<...>"
    }
}
```
`file_url` is a unique URL that points to the uploaded file which can be retrieved later.

### Retrieve file
```
"<file_url>" {
    METHOD: GET
}
```
The server will respond with the file data. File uploads and downloads are not authenticated and secured only by keeping the unique URL secret.


## Client Responsibilities
When receiving a message from the server, the client first needs to validate the signature against the public key of the sender.

### How to send a message?
There are two things to know about your recipient: their server address and public key. use these to fill out a `"chat"` message and your server will forward it to the correct destination.

### How do you know when you receive a message for you?
When receiving a chat message, you should attempt to decrypt the `symm_key` field, then use that to decrypt the `chat` field. If the result follows the format, then the message is directed to you. You can also check for your public key in the `participants` list.


## Server Responsibilities
A server is primarily a relay for messages. It does only a minimal amount of message parsing and state storage.

It is a server's responsibility to not forward garbage, so it should check all messages to ensure they follow a standard message format as above. This includes incoming (from other servers) and outgoing (from clients) messages.

A server is located by an address which opionally includes a port. The default port is the same as http[s]. 80 for non-TLS and 443 for TLS
- 10.0.0.27:8001
- my.awesomeserver.net
- localhost:666

### Stored state
- Client list. A server should listen to every `client_update` message and use this to keep an internal list of all connected clients in the neighbourhood.
- Files
- List of other servers in the neighbourhood

### Adding a new server to a neighbourhood
The server admins (Whoever is hosting the server) need to agree and each manually add the new server into the stored list.
If not all servers agree on who is in the neighbourhood, the neighbourhood enters an invalid state and it is not guaranteed that all clients will be able to communicate.


## Underlying technologies
The transport layer uses Websockets, meaning the server will need to be HTTP-capable. There are various websocket libraries for the popular programming languages that will handle this.

## Encryption
### Asymmetric Encryption
Asymmetric encryption and decryption is performed with RSA.
- Key size/Modulus length (n) = 2048 bits
- Public exponent (e) = 65537
- Padding scheme: OAEP with SHA-256 digest/hash function
- Public keys are exported in PEM encoding with PKCS8 format.

Signing and verification also uses RSA. It shares the same keys as encryption/decryption.
- Padding scheme: PSS with SHA-256 digest/hash function
- Salt length: 32 bytes

Symmetric encryption is performed with AES in GCM mode.
- Initialisation vector (IV) = 16 bytes (Must be randomly generated)
- Additional/associated data = not used (empty).
- Key length: 32 bytes (128 bits)
