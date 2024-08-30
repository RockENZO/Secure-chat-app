#include "server.h"
#include <iostream>

Server::Server(const std::string& address) : address(address) {}

void Server::start() {
    // Initialize WebSocket server and start listening
    std::cout << "Server started at " << address << std::endl;
    // WebSocket code to accept connections and handle messages
}

void Server::broadcastMessage(const Message& message) {
    for (auto& client : clients) {
        client.second.sendMessage(message);
    }
}

void Server::handleClientMessage(const Client& client, const Message& message) {
    if (message.getType() == "chat") {
        broadcastMessage(message);
    }
    // Handle other message types (e.g., hello, client update)
}

void Server::updateClientList() {
    // Update the list of clients connected to this server
    // Broadcast client list to other servers
}

void Server::handleNewClient(const Client& client) {
    clients[client.getFingerprint()] = client;
    updateClientList();
}

void Server::handleDisconnect(const Client& client) {
    clients.erase(client.getFingerprint());
    updateClientList();
}