#pragma once
#include <string>
#include "message.h"
#include "encryption.h"
#include <fstream>
#include <sstream>

class Client {
public:
    Client(const std::string& publicKey, const std::string& privateKey, const std::string& serverAddress);
    void connect();
    void sendMessage(const Message& message);
    std::string getFingerprint() const;


    void sendFile(const std::string& filePath, const std::string& serverAddress) {
        std::ifstream file(filePath, std::ios::binary);
        std::ostringstream oss;
        oss << file.rdbuf();
        std::string fileContent = oss.str();
        std::string encryptedFileContent = Encryption::encryptAES("my_secret_key", fileContent);

        Message message("file", {
            {"destination_servers", serverAddress},
            {"file_name", filePath},
            {"file_content", encryptedFileContent}
        });

        sendMessage(message);
    }

private:
    std::string publicKey;
    std::string privateKey;
    std::string fingerprint;
    std::string serverAddress;

    void generateFingerprint();
};