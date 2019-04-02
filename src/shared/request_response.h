
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

        explicit MessageNumberData(uint32_t first) : lastSent(first) {}
    };

    static std::map<uint32_t, MessageNumberData> messageNumbers;
public:
    static uint32_t &getNextNumber(uint32_t userId);
};

struct Request {
    enum class Type {
        LOGIN, LOGIN_COMPLETE, LOGOUT, CREATE, CREATE_COMPLETE,
        REMOVE, SEND, GET_ONLINE, FIND_USERS, KEY_BUNDLE_UPDATE
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
     *      3 - communication to other user
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
        DATABASE_USERLIST = 0x0110,
        DATABASE_RECEIVE = 0x0111,
        DATABASE_NOT_FOUD = 0x0151,
        USERNAME_NOT_VALID = 0x1150,
        FAILED_TO_DELETE_USER = 0x1151,
        
        USER_REGISTERED = 0x0300,

        GENERIC_SERVER_ERROR = 0x1000,
        INVALID_AUTH = 0x1200,
        FAILED_TO_CLOSE_CONNECTION = 0x1350,
        CHALLENGE_RESPONSE_NEEDED = 0x2200,
        BUNDLE_UPDATE_NEEDED = 0x2201,
        FAILED_TO_UPDATE_BUNDLE = 0x1100,
        KEY_BUNDLE_UPDATED = 0x0201
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
#endif //HELLOWORLD_SHARED_REQUEST_H_

