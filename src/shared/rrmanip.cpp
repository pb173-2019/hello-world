/**
 * @file rrmanip.cpp
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief definititons of memeber functions
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */


#include "rrmanip.h"
#include <algorithm>
#include "cstdlib"

using namespace helloworld;

RequestBuilder::RequestBuilder(uint32_t initialMessageNumber)
        : lastMessageNumber(initialMessageNumber) {}

void RRManipualator::setAuthenticationKey(std::vector<unsigned char> key) {
    authentificator.setKey(std::move(key));
}

void RequestBuilder::setMessageNumber(uint32_t newNumber) {
    lastMessageNumber = newNumber;
}


void RequestParser::setMessageNumber(uint32_t newNumber) {
    messageNumberSet = true;
    expectedMessageNumber = newNumber;
}

void RequestBuilder::writeTo(Request &request, std::ostream &output) {
    if (!output)
        throw Error("Wrong output stream");


    Request::Header newHeader{
            lastMessageNumber + 1,
            static_cast<uint32_t >(request.payload.size()),
            static_cast<unsigned char>(request.type),
            {0}
    };

    std::vector<unsigned char> rawRequest;

    _writeTo(newHeader, request.payload, rawRequest);

    lastMessageNumber += 1;
    request.messageNumber = lastMessageNumber;

    output.write(reinterpret_cast<char *>(rawRequest.data()), rawRequest.size()); //NOLINT
}

RequestParser::RequestParser() : messageNumberSet{false}, expectedMessageNumber{0} {}


Request RequestParser::parseRequest(std::istream &input) {
    Request::Header newHeader;
    Request result;

    _readHeader(input, newHeader);

    result.type = static_cast<Request::Type>(newHeader.type);
    result.messageNumber = newHeader.messageNumber;

    if (!Request::isValidType(result.type))
        throw Error("Invalid request type");
    if (expectedMessageNumber != result.messageNumber && messageNumberSet)
        throw Error("Invalid message number");

    _readPayload(input, newHeader, result.payload);
    expectedMessageNumber = result.messageNumber + 1;
    messageNumberSet = true;

    return result;
}

void ResponseBuilder::writeTo(Response &response, std::ostream &output) {

    if (!output)
        throw Error("Wrong output stream");

    Response::Header newHeader{
            response.messageNumber,
            static_cast<uint32_t >(response.payload.size()),
            static_cast<unsigned char>(response.type),
            {0}
    };

    std::vector<unsigned char> rawResponse;

    _writeTo(newHeader, response.payload, rawResponse);

    output.write(reinterpret_cast<char *>(rawResponse.data()), rawResponse.size()); //NOLINT

}

Response ResponseParser::parseResponse(std::istream &input) {

    Response::Header newHeader;
    Response result;

    _readHeader(input, newHeader);

    result.type = static_cast<Response::Type>(newHeader.type);
    result.messageNumber = newHeader.messageNumber;

    if (!Response::isValidType(result.type))
        throw Error("Invalid request type");

    _readPayload(input, newHeader, result.payload);

    return result;
}
