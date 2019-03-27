
#include "request_response.h"
using namespace helloworld;
std::map<uint32_t, MessageNumberGenerator::MessageNumberData> MessageNumberGenerator::messageNumbers{};

uint32_t &MessageNumberGenerator::getNextNumber(uint32_t userId) {
    return messageNumbers[userId].lastSent;
}

std::vector<unsigned char> Request::Header::serialize() const {
    std::vector<unsigned char> ret;
    const_cast<Header *>(this)->messageNumber = MessageNumberGenerator::getNextNumber(userId)++;
    addNumeric(ret, static_cast<uint32_t >(type));
    addNumeric(ret, messageNumber);
    addNumeric(ret, userId);
    return ret;
}

Request::Header Request::Header::deserialize(const std::vector<unsigned char> &data) {
    Header ret;
    uint64_t offset = 0;
    uint32_t type;
    offset += getNumeric(data, offset, type);
    ret.type = static_cast<Type >(type);
    offset += getNumeric(data, offset, ret.messageNumber);
    getNumeric(data, offset, ret.userId);
    return ret;
}

Response::Header  Response::Header::deserialize(const std::vector<unsigned char> &data) {
    Header ret;
    uint64_t offset = 0;
    uint32_t type;
    offset += getNumeric(data, offset, type);
    ret.type = static_cast<Type >(type);
    offset += getNumeric(data, offset, ret.messageNumber);
    getNumeric(data, offset, ret.userId);
    return ret;
}

std::vector<unsigned char> Response::Header::serialize() const  {
    std::vector<unsigned char> ret;
    addNumeric(ret, static_cast<uint32_t >(type));
    addNumeric(ret, messageNumber);
    addNumeric(ret, userId);
    return ret;
}