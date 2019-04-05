
#include "request_response.h"
using namespace helloworld;
std::map<uint32_t, MessageNumberGenerator::MessageNumberData> MessageNumberGenerator::messageNumbers{};

uint32_t &MessageNumberGenerator::getNextNumber(uint32_t userId) {
    return messageNumbers[userId].lastSent;
}

serialize::structure& Request::Header::serialize(serialize::structure& result) const {
    const_cast<Header *>(this)->messageNumber = MessageNumberGenerator::getNextNumber(userId)++;
    serialize::serialize(static_cast<uint32_t >(type), result);
    serialize::serialize(messageNumber, result);
    serialize::serialize(userId, result);
    return result;
}

Request::Header Request::Header::deserialize(const serialize::structure &data, uint64_t& from) {
    Header ret;
    uint32_t type =
            serialize::deserialize<uint32_t >(data, from);
    ret.type = static_cast<Type >(type);
    ret.messageNumber =
            serialize::deserialize<decltype(ret.messageNumber)>(data, from);
    ret.userId =
            serialize::deserialize<decltype(ret.userId)>(data, from);
    return ret;
}

Response::Header  Response::Header::deserialize(const serialize::structure &data, uint64_t& from) {
    Header ret;
    uint32_t type =
            serialize::deserialize<uint32_t >(data, from);
    ret.type = static_cast<Type >(type);
    ret.messageNumber =
            serialize::deserialize<decltype(ret.messageNumber)>(data, from);
    ret.userId =
            serialize::deserialize<decltype(ret.userId)>(data, from);
    return ret;
}

serialize::structure& Response::Header::serialize(serialize::structure& result) const  {
    serialize::serialize(static_cast<uint32_t >(type), result);
    serialize::serialize(messageNumber, result);
    serialize::serialize(userId, result);
    return result;
}