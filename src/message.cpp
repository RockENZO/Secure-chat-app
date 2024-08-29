#include "message.h"

Message::Message(const std::string& type, const nlohmann::json& data)
    : type(type), data(data) {}

std::string Message::toJson() const {
    nlohmann::json msg;
    msg["type"] = type;
    msg["data"] = data;
    return msg.dump();
}

std::string Message::getType() const {
    return type;
}