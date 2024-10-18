# Testing Secure Chat Application

## Logging in
1. Entering username.
**Test Case:**

    - user inputs their username in the login window.
**Expected outcome:**

    - Username is accepted if valid (non-empty, alphanumeric).
    - Error handling for when no username is entered.
    - If no username is entered, the window should close prompting user to start client side         server again.

3. Entering password.
**Test Case:**
User inputs a password to authenticate.
**Expected outcome:**
    - users unable to access chat app
    - Error handling for no password entered.
    - input sanitisation

4. Multiple client joining.
**Test Case:**
Multiple clients connect to the server at the same time.
**Expected outcome:**
    - All clients should appear in the connected users list.
    - Server should handle multiple connections without dropping any.

## Messaging
1. Public messaging.
    - A user sends a public message to all connected users.
**Expected outcome:**

    - The message should be displayed on all connected clients' chat windows
    - Input sanitisation to prevent malicous actors
2. Private messaging
**Test Case:**
A user sends a private message to another user.
**Expected outcome:**
    - The message should only appear in the chat window of the sender and receiver.
    - A visual indicator is there to differentiate private messages from public ones.
    - Input sanitisation to prevent malicous actors
3. Handling Message Encryption and Decryption
**Test Case:**
Verify that messages are properly encrypted before transmission and decrypted upon reception.
**Expected outcome:**
    - All messages must be encrypted using RSA for private keys and AES for session keys.
    - If decryption fails, show: "Message could not be decrypted. Please try again."
  
    - 
**Test Case:**
**Expected outcome:**

