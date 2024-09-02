#include <iostream>
#include <thread>
#include <string>
#include "server.h"
#include "client.h"
#include "message.h"
#include "encryption.h"

void runServer(const std::string& address) {
    Server server(address);
    server.start();

    while (true) {
        Message message = server.receiveMessage();
        server.handleMessage(message);
    }
}

void runClient(const std::string& publicKey, const std::string& privateKey, const std::string& serverAddress) {
    Client client(publicKey, privateKey, serverAddress);
    client.connect();

    std::string input;
    while (true) {
        std::cout << "Enter message or type 'sendfile <path>' to send a file (type 'exit' to quit): ";
        std::getline(std::cin, input);

        if (input == "exit") {
            break;
        } else if (input.rfind("sendfile ", 0) == 0) {
            std::string filePath = input.substr(9);
            client.sendFile(filePath, serverAddress);
        } else {
            // Encrypt the message before sending
            std::string encryptedMessage = Encryption::encryptAES("my_secret_key", input);
            Message message("chat", {
                {"destination_servers", {serverAddress}},
                {"chat", encryptedMessage}
            });

            client.sendMessage(message);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <publicKey> <privateKey> <serverAddress>\n";
        std::cerr << "Mode can be 'server' or 'client'\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string publicKey = argv[2];
    std::string privateKey = argv[3];
    std::string serverAddress = argv[4];

    if (mode == "server") {
        // Run the server in a separate thread
        std::thread serverThread(runServer, serverAddress);
        serverThread.join();
    } else if (mode == "client") {
        // Run the client in the main thread
        runClient(publicKey, privateKey, serverAddress);
    } else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}