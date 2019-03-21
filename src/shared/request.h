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
        /**
         * number order in type: 1 | 2 | 3 | 4
         * 1:   0 - ok
         *      1 - error
         *      2 - reponse needed
         *      ...
         * 2:   0 - generic event,
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
