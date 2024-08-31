#pragma once
#include <string>
#include "../external/rapidjson/include/rapidjson/document.h"
#include "../external/rapidjson/include/rapidjson/writer.h"
#include "../external/rapidjson/include/rapidjson/stringbuffer.h"

class Message {
public:
    Message(const std::string& type, const rapidjson::Document data);
    std::string toJson() const;
    std::string getType() const;
    const rapidjson::Document& getData() const;

private:
    std::string type;
    rapidjson::Document data;
};