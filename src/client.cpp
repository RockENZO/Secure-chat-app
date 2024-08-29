#include "client.h"
#include <openssl/sha.h>
#include <iostream>

Client::Client(const std::string& pubKey, const std::string& privKey, const std::string& serverAddr)
    : publicKey(pubKey), privateKey(privKey), serverAddress(serverAddr) {
    generateFingerprint();
}

void Client::connect() {
    std::cout << "Connecting to server at " << serverAddress << std::endl;
    // WebSocket code to connect to server
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