#include "message.h"

Message::Message(const std::string& type, rapidjson::Document data)
    : type(type), data(std::move(data)) {}

std::string Message::toJson() const {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  writer.String("type");
  writer.String(type.c_str());
  writer.String("data");
  data.Accept(writer);
  writer.EndObject();
  return buffer.GetString();
}

std::string Message::getType() const { return type; }

const rapidjson::Document& Message::getData() const {
    return data;
}