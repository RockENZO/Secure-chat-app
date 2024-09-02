#pragma once
#include <string>
#include <map>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

class Message {
public:
    std::string type;
    std::map<std::string, std::string> data;

    Message(const std::string& type, const std::map<std::string, std::string>& data)
        : type(type), data(data) {}

    bool isFileTransfer() const {
        return type == "file";
    }

    std::string toJson() const {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        writer.StartObject();
        writer.Key("type");
        writer.String(type.c_str());
        writer.Key("data");
        writer.StartObject();
        for (const auto& pair : data) {
            writer.Key(pair.first.c_str());
            writer.String(pair.second.c_str());
        }
        writer.EndObject();
        writer.EndObject();
        return buffer.GetString();
    }
};