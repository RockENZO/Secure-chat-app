#include <iostream>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <json/json.h>
#include <map>
#include <set>
#include <string>
#include <functional>  // Include this for std::bind and std::placeholders

typedef websocketpp::server<websocketpp::config::asio> server;

std::map<std::string, websocketpp::connection_hdl> clients;
std::set<websocketpp::connection_hdl, std::owner_less<websocketpp::connection_hdl>> connections;

void on_message(server* s, websocketpp::connection_hdl hdl, server::message_ptr msg) {
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(msg->get_payload(), root)) {
        std::cerr << "Failed to parse message" << std::endl;
        return;
    }

    std::string type = root["data"]["type"].asString();
    if (type == "hello") {
        std::string public_key = root["data"]["public_key"].asString();
        clients[public_key] = hdl;
        std::cout << "Client connected with public key: " << public_key << std::endl;
    } else if (type == "chat") {
        std::string destination_server = root["data"]["destination_servers"][0].asString();
        auto it = clients.find(destination_server);
        if (it != clients.end()) {
            s->send(it->second, msg->get_payload(), msg->get_opcode());
        }
    }
}

void on_open(server* s, websocketpp::connection_hdl hdl) {
    connections.insert(hdl);
}

void on_close(server* s, websocketpp::connection_hdl hdl) {
    connections.erase(hdl);
    for (auto it = clients.begin(); it != clients.end(); ) {
        if (it->second.lock() == hdl.lock()) {
            it = clients.erase(it);
        } else {
            ++it;
        }
    }
}

int main() {
    server print_server;

    print_server.set_message_handler(std::bind(&on_message, &print_server, std::placeholders::_1, std::placeholders::_2));
    print_server.set_open_handler(std::bind(&on_open, &print_server, std::placeholders::_1));
    print_server.set_close_handler(std::bind(&on_close, &print_server, std::placeholders::_1));

    print_server.init_asio();
    print_server.listen(9002);
    print_server.start_accept();

    print_server.run();
}