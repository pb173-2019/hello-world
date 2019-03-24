
/**
 * @file request.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief request and response structures
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_REQUEST_H
#define HELLOWORLD_REQUEST_H

#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include "serializable.h"
#include "random.h"

namespace helloworld {

class MessageNumberGenerator {
    struct MessageNumberData {
        uint32_t lastSent;

        MessageNumberData() : lastSent(static_cast<uint32_t>(Random{}.getBounded(0, 256))) {}
    };

    static std::map<uint32_t, MessageNumberData> messageNumbers;
public:
    static uint32_t &getNextNumber(uint32_t userId);
};

struct Request {
    enum class Type {
        LOGIN, LOGIN_COMPLETE, LOGOUT, CREATE, CREATE_COMPLETE, DELETE, SEND, RECEIVE, FIND_USER, GET_ONLINE
    };

    struct Header : Serializable<Request::Header> {
        Type type{};
        uint32_t messageNumber{};
        uint32_t userId{};

        Header() = default;

        Header(Type type, uint32_t messageNumber, uint32_t userId)
                : type(type), messageNumber(messageNumber), userId(userId) {}

        std::vector<unsigned char> serialize() const override;

        static Request::Header deserialize(const std::vector<unsigned char> &data);
    };

    Header header;
    std::vector<unsigned char> payload;

};

struct Response {
    /**
     * number order in type: 1 | 2 | 3 | 4
     * 1:   0 - ok
     *      1 - error
     *      2 - response needed
     *      ...
     * 2:   0 - generic event
     *      1 - database event
     *      2 - security event
     *      3 - channel event
     *      ...
     * 3 & 4 - further specification
     */
    enum class Type {
        OK = 0x0080,

        DATABASE_NOT_FOUD = 0x0150,
        USERNAME_NOT_VALID = 0x1150,

        USER_REGISTERED = 0x0300,
        USER_AUTHENTICATED = 0x0301,

        GENERIC_SERVER_ERROR = 0x1000,
        INVALID_AUTH = 0x1200,
        INVALID_MAC = 0x1201,
        INVALID_MSG_NUM = 0x1050,

        CHALLENGE_RESPONSE_NEEDED = 0x2200,
    };

    struct Header : Serializable<Response::Header> {
        Type type{};
        uint32_t messageNumber{};
        uint32_t userId{};

        Header() = default;

        Header(Type type, uint32_t messageNumber, uint32_t userId)
                : type(type), messageNumber(messageNumber), userId(userId) {}

        std::vector<unsigned char> serialize() const override;

        static Response::Header deserialize(const std::vector<unsigned char> &data);
    };

    Header header;
    std::vector<unsigned char> payload;

};

} // namespace helloworld
#endif //HELLOWORLD_REQUEST_H

