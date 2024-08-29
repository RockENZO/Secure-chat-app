#pragma once
#include <string>
#include <nlohmann/json.hpp>

class Message {
public:
    Message(const std::string& type, const nlohmann::json& data);
    std::string toJson() const;
    std::string getType() const;

private:
    std::string type;
    nlohmann::json data;
};