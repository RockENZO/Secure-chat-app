#include "server.h"
#include <iostream>

Server::Server(const std::string& address) : address(address) {}

void on_open_server(websocketpp::connection_hdl hdl) {
    std::cout << "Client connected" << std::endl;
}

void on_close_server(websocketpp::connection_hdl hdl) {
    std::cout << "Client disconnected" << std::endl;
}

void on_message_server(websocketpp::connection_hdl hdl, WebSocketServer::message_ptr msg) {
    std::cout << "Message received: " << msg->get_payload() << std::endl;
}

void Server::start() {
    std::cout << "Server started at " << address << std::endl;

    try {
        wsServer.init_asio();
        wsServer.set_access_channels(websocketpp::log::alevel::all);
        wsServer.clear_access_channels(websocketpp::log::alevel::frame_payload);

        wsServer.set_open_handler(&on_open_server);
        wsServer.set_close_handler(&on_close_server);
        wsServer.set_message_handler(&on_message_server);

        wsServer.listen(9002);
        wsServer.start_accept();
        wsServer.run();
    } catch (websocketpp::exception const & e) {
        std::cout << e.what() << std::endl;
    }
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