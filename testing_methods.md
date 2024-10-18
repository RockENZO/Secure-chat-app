# Testing Secure Chat Application

## Logging in
1. Entering username.
    - Error handling for when no username is entered.
2. Entering password.
    - Error handling for no password entered.
3. Multiple client joining.
    - Checking connected username list is accurate.
4. Sanitisation Check
    - Tested for Cross-Site Scripting (XSS)
    - Tested for SQL Injection
    - Tested for Command Injection
    - Tested for Input Limit
    - Tested for HTML Injection
    - Tested for URL and Script Injection
    - Tested out special character such as '<' and '>'

## Messaging
1. Public messaging.
    - Message is shown to all connected users.
2. Private messaging.
    - Private message only shown to selected recipient.
3. Input Sanitisation Check.
    - Tested for Cross-Site Scripting (XSS)
    - Tested for SQL Injection
    - Tested for Command Injection
    - Tested for Input Limit
    - Tested for HTML Injection
    - Tested for URL and Script Injection
    - Tested out special character such as '<' and '>'

## File Transfer
1. Functionality on both Linux and macOS
    - Works on both operating system.
2. Sending different files.
    - Attempted images, text files, videos.
    - Check received files to ensure same as original file.
3. Overwrite check
    - Prompt receiver if saving with same name as existing file.
4. Stopping Mid-Process.
    - If sender exits when choosing file to send.
    - If receiver exits when choosing name to save file as.
5. Error handling
    - Typing name of file that does not exist in directory.
    - File size exceeding file size limit.