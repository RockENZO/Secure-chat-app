#pragma once
#include <string>
#include <map>
#include <vector>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include "client.h"
#include "message.h"

typedef websocketpp::server<websocketpp::config::asio> WebSocketServer;

class Server {
public:
    Server(const std::string& address);
    void start();
    void broadcastMessage(const Message& message);
    void handleClientMessage(const Client& client, const Message& message);
    void updateClientList();

private:
    std::string address;
    std::map<std::string, Client> clients;  // Keyed by client fingerprint
    std::vector<std::string> serverList;  // Other servers in the neighbourhood
    WebSocketServer wsServer;

    void handleNewClient(const Client& client);
    void handleDisconnect(const Client& client);
};