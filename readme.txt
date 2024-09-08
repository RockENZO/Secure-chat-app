1. Linux / macOS:
Open your terminal.

Navigate to the directory where your Python project (with server.py and client.py) is located, using the cd command.

Example:

bash
cd /path/to/your/project-directory

Type the openssl command: 
bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

Follow the prompts to provide information for the certificate. After running the command, two files, key.pem and cert.pem, will be generated in the current directory.


2. Windows:
You need to have OpenSSL installed on your system. If you don't have it installed, you can download it from Win32 OpenSSL and follow the instructions to install it.

Open Command Prompt or PowerShell as an administrator.

Navigate to your project directory using the cd command:

Example:

cmd
cd C:\path\to\your\project-directory

Run the openssl command:
cmd
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

Provide the necessary information for the certificate. Once done, key.pem and cert.pem files will be generated in your project directory.


3. WSL (Windows Subsystem for Linux):
If you're using WSL on Windows, you can open a WSL terminal (e.g., Ubuntu).
Navigate to your project directory and run the same openssl command as on Linux/macOS.

Example:
bash
cd /mnt/c/Users/your-username/path/to/your/project-directory

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes