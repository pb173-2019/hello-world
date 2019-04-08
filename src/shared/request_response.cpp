
#include "request_response.h"
using namespace helloworld;


bool MessageNumberGenerator::checkIncomming(const Request& data) {
    if (!_set) {
        _set = true;
        _nIncomming = data.header.messageNumber;
        return true;
    }
    if (data.header.messageNumber != _nIncomming + 1)
        return false;


    _unresolvedNumbers.insert(data.header.messageNumber);
    ++_nIncomming;
    return true;
}

bool MessageNumberGenerator::checkIncomming(const Response& data) {

    // check whether it is response to request
    auto it = _unresolvedNumbers.find(data.header.messageNumber);
    if (it != _unresolvedNumbers.end()) {
        _unresolvedNumbers.erase(data.header.messageNumber);
        return true;
    }
    if (!_set) {
        _set = true;
        _nIncomming = data.header.messageNumber;
        return true;
    }
    if (data.header.messageNumber != _nIncomming + 1)
        return false;

    _unresolvedNumbers.insert(data.header.messageNumber);
    ++_nIncomming;
    return true;
}

void MessageNumberGenerator::setNumber(Request& r) {
    r.header.messageNumber = _nOutgoing++;
    _unresolvedNumbers.insert(r.header.messageNumber);
}

void MessageNumberGenerator::setNumber(Response& r) {
    // check whether it is response to request
    auto it = _unresolvedNumbers.find(r.header.messageNumber);
    if (it != _unresolvedNumbers.end()) {
        _unresolvedNumbers.erase(r.header.messageNumber);
        return;
    }
    // if it is unsolicitated
    r.header.messageNumber = _nOutgoing++;
}

serialize::structure& Request::Header::serialize(serialize::structure& result) const {

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