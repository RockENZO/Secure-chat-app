#pragma once
#include <string>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

class Message {
public:
    Message(const std::string& type, const rapidjson::Document& data);
    std::string toJson() const;
    std::string getType() const;

private:
    std::string type;
    rapidjson::Document data;
};