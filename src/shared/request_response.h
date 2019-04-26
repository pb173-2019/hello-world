
/**
 * @file request_response.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief request and response structures
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_REQUEST_H_
#define HELLOWORLD_SHARED_REQUEST_H_

#include <cstdint>
#include <vector>
#include <type_traits>
#include "serializable.h"
#include "random.h"
#include <set>

namespace helloworld {

struct Request {
    enum class Type {
        LOGIN, LOGOUT, CREATE, CHALLENGE, CHECK_INCOMING,
        REMOVE, SEND, GET_ONLINE, FIND_USERS, KEY_BUNDLE_UPDATE, GET_RECEIVERS_BUNDLE
    };

    struct Header : public Serializable<Request::Header> {
        Type type = Type::LOGIN;
        uint32_t messageNumber = 0;
        uint32_t userId = 0;
        uint32_t fromId = userId;

        Header() = default;

        Header(Type type, uint32_t userId) : type(type), userId(userId) {}

        Header(Type type, uint32_t userId, uint32_t fromId) : type(type), userId(userId), fromId(fromId) {}

        serialize::structure& serialize(serialize::structure& result) const override;
        serialize::structure serialize() const override {
            serialize::structure result;
            return serialize(result);
        }

        static Header deserialize(const serialize::structure &data, uint64_t& from);
        static Header deserialize(const std::vector<unsigned char> &data) {
            uint64_t from = 0;
            return deserialize(data, from);
        };
    };

    Header header;
    std::vector<unsigned char> payload;
};

struct Response {

    enum class Type {
        OK = 0x0080,
        USERLIST,
        RECEIVE_OLD,
        RECEIVE,
        RECEIVER_BUNDLE_SENT,
        DATABASE_NOT_FOUD,
        USERNAME_NOT_VALID,
        FAILED_TO_DELETE_USER,
        USER_REGISTERED,
        GENERIC_SERVER_ERROR,
        INVALID_AUTH,
        FAILED_TO_CLOSE_CONNECTION,
        CHALLENGE_RESPONSE_NEEDED,
        BUNDLE_UPDATE_NEEDED,
        FAILED_TO_UPDATE_BUNDLE
    };

    struct Header : public Serializable<Response::Header> {
        Type type = Type::OK;
        uint32_t messageNumber = 0;
        uint32_t userId = 0;
        uint32_t fromId = userId;

        Header() = default;

        Header(Type type, uint32_t userId) : type(type), userId(userId) {}

        Header(Type type, uint32_t userId, uint32_t fromId) : type(type), userId(userId), fromId(fromId) {}

        serialize::structure& serialize(serialize::structure& result) const override;
        serialize::structure serialize() const override {
            serialize::structure result;
            return serialize(result);
        }

        static Header deserialize(const serialize::structure &data, uint64_t& from);
        static Header deserialize(const std::vector<unsigned char> &data) {
            uint64_t from = 0;
            return deserialize(data, from);
        };
    };

    Header header;
    std::vector<unsigned char> payload;

    Response() = default;
    Response(Type type, uint32_t userId, uint32_t fromId) : header(type, userId, fromId) {}
    Response(Type type, uint32_t userId, uint32_t fromId, std::vector<unsigned char> payload)
                : header(type, userId, fromId), payload(std::move(payload)) {}
    Response(Header header) : header(std::move(header)) {}
    Response(Header header, std::vector<unsigned char> payload)
                : header(std::move(header)), payload(std::move(payload)) {}

    Response(Type type, uint32_t userId) : header(type, userId) {}
    Response(Type type, uint32_t userId, std::vector<unsigned char> payload)
                : header(type, userId), payload(std::move(payload)) {}

};


class MessageNumberGenerator {

    bool _set{false};
    std::set<uint32_t > _unresolvedNumbers;
    uint32_t _nIncomming = 0;
    uint32_t _nOutgoing = 0;

public:
    MessageNumberGenerator() : _nOutgoing(static_cast<uint32_t>(Random{}.getBounded(0, UINT32_MAX))) {}

    bool checkIncomming(const Request& data);

    bool checkIncomming(const Response& data);

    void setNumber(Request& r);

    void setNumber(Response& r);
};


} // namespace helloworld
#endif //HELLOWORLD_SHARED_REQUEST_H_

