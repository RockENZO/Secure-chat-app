#include "client.h"
#include <openssl/sha.h>
#include <iostream>

Client::Client(const std::string& pubKey, const std::string& privKey, const std::string& serverAddr)
    : publicKey(pubKey), privateKey(privKey), serverAddress(serverAddr) {
    generateFingerprint();
}

void on_open(websocketpp::connection_hdl hdl) {
    std::cout << "Connection opened" << std::endl;
}

void on_close(websocketpp::connection_hdl hdl) {
    std::cout << "Connection closed" << std::endl;
}

void on_message(websocketpp::connection_hdl hdl, WebSocketClient::message_ptr msg) {
    std::cout << "Message received: " << msg->get_payload() << std::endl;
}

void Client::connect() {
    std::cout << "Connecting to server at " << serverAddress << std::endl;

    try {
        wsClient.init_asio();
        wsClient.set_access_channels(websocketpp::log::alevel::all);
        wsClient.clear_access_channels(websocketpp::log::alevel::frame_payload);

        wsClient.set_open_handler([this](websocketpp::connection_hdl hdl) {
            connectionHandle = hdl;
            on_open(hdl);
        });
        wsClient.set_close_handler(&on_close);
        wsClient.set_message_handler(&on_message);

        websocketpp::lib::error_code ec;
        WebSocketClient::connection_ptr con = wsClient.get_connection(serverAddress, ec);
        if (ec) {
            std::cout << "Could not create connection because: " << ec.message() << std::endl;
            return;
        }

        wsClient.connect(con);
        wsClient.run();
    } catch (websocketpp::exception const & e) {
        std::cout << e.what() << std::endl;
    }
}

void Client::sendMessage(const Message& message) {
    // Serialize and send message over WebSocket
    std::cout << "Sending message: " << message.toJson() << std::endl;
}

std::string Client::getFingerprint() const {
    return fingerprint;
}

void Client::generateFingerprint() {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)publicKey.c_str(), publicKey.size(), hash);
    fingerprint = std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}