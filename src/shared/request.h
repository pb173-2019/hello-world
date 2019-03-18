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
#include "hmac.h"
#include <vector>

namespace helloworld {

    struct Request {
        enum class Type {
            LOGIN, LOGIN_COMPLETE, LOGOUT, CREATE, CREATE_COMPLETE, DELETE, SEND, RECEIVE, FIND
        };

        /**
        * @brief Checks whether type value is one of defined values
        *
        * @param  type. which validity is being checked
        * @return bool true if type is valid, false otherwise
        */
        static bool isValidType(Type type) { return Type::LOGIN <= type && type <= Type::FIND; }

        struct Header {
            uint32_t messageNumber;
            uint32_t payloadLength;
            unsigned char type;
            unsigned char hmac[HMAC::hmac_size];
        };

        Type type;
        std::vector<unsigned char> payload;
        uint32_t messageNumber;
    };

    struct Response {
        enum class Type {
            OK = 128, NOT_FOUD, INVALID_AUTH, INVALID_MSG_NUM, SERVER_ERROR, CHALLENGE_RESPONSE_NEEDED
        };

        /**
        * @brief Checks whether type value is one of defined values
        *
        * @param type. which validity is being checked
        * @return bool true if type is valid, false otherwise
        */
        static bool isValidType(Type type) { return Type::OK <= type && type <= Type::CHALLENGE_RESPONSE_NEEDED; }

        struct Header {
            uint32_t messageNumber;
            uint32_t payloadLength;
            unsigned char type;
            unsigned char hmac[HMAC::hmac_size];
        };

        Type type;
        std::vector<unsigned char> payload;
        uint32_t messageNumber;
    };


}; // namespace helloworld
#endif //HELLOWORLD_REQUEST_H
