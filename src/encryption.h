#pragma once
#include <string>

class Encryption {
public:
    static std::string encryptRSA(const std::string& publicKey, const std::string& message);
    static std::string decryptRSA(const std::string& privateKey, const std::string& encryptedMessage);
    static std::string encryptAES(const std::string& key, const std::string& message);
    static std::string decryptAES(const std::string& key, const std::string& encryptedMessage);
};