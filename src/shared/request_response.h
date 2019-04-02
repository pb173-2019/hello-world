
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

    enum class Type {
        OK = 0x0080,
        USERLIST,
        RECEIVE_OLD,
        RECEIVE,
        RECEIVER_BUNDLE,
        DATABASE_NOT_FOUD,
        USERNAME_NOT_VALID,
        FAILED_TO_DELETE_USER,
        USER_REGISTERED,
        GENERIC_SERVER_ERROR,
        INVALID_AUTH,
        FAILED_TO_CLOSE_CONNECTION,
        CHALLENGE_RESPONSE_NEEDED,
        BUNDLE_UPDATE_NEEDED,
        FAILED_TO_UPDATE_BUNDLE,
        KEY_BUNDLE_UPDATED
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

