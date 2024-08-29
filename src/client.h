#pragma once
#include <string>
#include "message.h"

class Client {
public:
    Client(const std::string& publicKey, const std::string& privateKey, const std::string& serverAddress);
    void connect();
    void sendMessage(const Message& message);
    std::string getFingerprint() const;

private:
    std::string publicKey;
    std::string privateKey;
    std::string fingerprint;
    std::string serverAddress;

    void generateFingerprint();
};