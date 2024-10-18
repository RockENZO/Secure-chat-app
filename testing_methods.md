# Testing Secure Chat Application
## Logging In
### Entering Username
**Test Case:**\
User inputs their username in the login window.\
**Expected outcome:**\
    - Username is accepted if valid (non-empty, alphanumeric).\
    - Error handling for when no username is entered.\
    - If no username is entered, the window should close prompting user to start client side server again.

## Entering Password
**Test Case:**\
User inputs a password to authenticate.\
**Expected outcome:**\
    - Users unable to access chat app\
    - Error handling for no password entered.\
    - Input sanitisation

## Multiple client joining
**Test Case:**\
Multiple clients connect to the server at the same time.\
**Expected outcome:**\
    - All clients should appear in the connected users list.\
    - Server should handle multiple connections without dropping any.

## Public messaging
**Test Case:**\
A user sends a public message to all connected users.\
**Expected outcome:**\
    - The message should be displayed on all connected clients' chat windows\
    - Input sanitisation to prevent malicous actors

## Private messaging
**Test Case:**\
A user sends a private message to another user.\
**Expected outcome:**\
    - The message should only appear in the chat window of the sender and receiver.\
    - A visual indicator is there to differentiate private messages from public ones.\
    - Input sanitisation to prevent malicous actors.

## Handling Message Encryption and Decryption
**Test Case:**\
Verify that messages are properly encrypted before transmission and decrypted upon reception.\
**Expected outcome:**\
    - All messages must be encrypted using RSA for private keys and AES for session keys.\
    - If decryption fails, show: "Message could not be decrypted. Please try again."
## File Uploads
**Test Case:**\
    - Users upload files via the chat interface.\
**Expected outcome:**\
    - Files are uploaded successfully and "saved on the server" {not sure on this part}
    - Users recive confermation message as to wheather they are willing to acppect the file from       a user or not.\
    - if the file size exceeeds the limit it will prooced to cancel the file upload.\
## Downloading Files
**Test Case:**\
    - Users download files shared in the chat.
**Expected outcome:**\
    - Files are downloaded securely without corruption.
    - Reciver recives a conferation message once a file is accepted
##  Encryption and Certificate Management
**Test Case:**\
    - Ensure certificates are validated upon connection.
**Expected outcome:**\
    - Connections should be established only if certificates are trusted.
## RSA Key Pair Generation and Storage
**Test Case:**\
    - Verify that RSA key pairs are correctly generated and stored.
**Expected outcome:**\
    - Keys should be stored securely in the user's system.
    - The application must retrieve and use the correct keys for encryption and decryption.

## Server-to-Server Communication
like not 100% sure what teh test case adn expected out should would love so help with this part
**Test Case:**\
**Expected outcome:**\

## Encrypted Server Messages
**Test Case:**\
    - Verify that server messages are encrypted before transmission.
**Expected outcome:**\
All server-to-server messages must follow the encryption protocol using AES.
## Error handling and edge cases
## Handling Disconnected Clients
**Test Case:**\
    - Test how the application behaves when a client disconnects unexpectedly.
**Expected outcome:**\
    - The disconnected user should be removed from the user list.
    - Message sent to a disconnected user will return the following text "No other users               connected".
## Testing High Load and Performance
**Test Case:**\
    - Simulate multiple users connecting and sending messages and uploading files simultaneously.
**Expected outcome:**\
    - The system should handle high loads without crashing or slowing down.
## Preventing Replay Attacks
**Test Case:**\
    - Test whether the application detects and prevents message replay attacks.
**Expected outcome:**\
    - The system should reject any duplicate messages with the same counter value.

## Summary 
The testing plan for the secure chat application ensures robust functionality, security, and performance. Key areas include user authentication, messaging, file handling, encryption, and server communication. Through this comprehensive error handling and edge case testing, the platform maintains stability across various usage scenarios. This robust approach ensures reliable performance and seamless user experience while using our chat app.



