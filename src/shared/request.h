
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

            MessageNumberData() : lastSent(Random{}.getBounded(0, UINT32_MAX)) {}
        };

        static std::map<uint32_t, MessageNumberData> messageNumbers;
    public:
        static uint32_t &getNextNumber(uint32_t userId) {
            return messageNumbers[userId].lastSent;
        }

    };

    std::map<uint32_t, MessageNumberGenerator::MessageNumberData> MessageNumberGenerator::messageNumbers{};

    struct Request {
        enum class Type {
            LOGIN, LOGOUT, CREATE, DELETE, SEND, RECEIVE, FIND
        };

        /**
        * @brief Checks whether type value is one of defined values
        *
        * @param  type. which validity is being checked
        * @return bool true if type is valid, false otherwise
        */
        static bool isValidType(Type type) { return Type::LOGIN <= type && type <= Type::FIND; }

        struct Header : Serializable<Request::Header> {
            Type type;
            uint32_t messageNumber;
            uint32_t userId;

            std::vector<unsigned char> serialize() const override {
                std::vector<unsigned char> ret;
                const_cast<Header *>(this)->messageNumber = MessageNumberGenerator::getNextNumber(userId)++;
                addNumeric(ret, static_cast<uint32_t >(type));
                addNumeric(ret, messageNumber);
                addNumeric(ret, userId);
                return ret;
            }

            static Request::Header deserialize(const std::vector<unsigned char> &data) {
                Header ret;
                uint64_t offset = 0;
                uint32_t type;
                offset += getNumeric(data, offset, type);
                ret.type = static_cast<Type >(type);
                offset += getNumeric(data, offset, ret.messageNumber);
                getNumeric(data, offset, ret.userId);
                return ret;
            }
        };

        Header header;
        std::vector<unsigned char> payload;

    };

    struct Response {
        enum class Type {
            OK = 128, NOT_FOUD, INVALID_AUTH, INVALID_MSG_NUM
        };

        /**
        * @brief Checks whether type value is one of defined values
        *
        * @param type. which validity is being checked
        * @return bool true if type is valid, false otherwise
        */
        static bool isValidType(Type type) { return Type::OK <= type && type <= Type::INVALID_MSG_NUM; }

        struct Header : Serializable<Response::Header> {
            Type type;
            uint32_t messageNumber;
            uint32_t userId;

            std::vector<unsigned char> serialize() const override {
                std::vector<unsigned char> ret;
                addNumeric(ret, static_cast<uint32_t >(type));
                addNumeric(ret, messageNumber);
                addNumeric(ret, userId);
                return ret;
            }

            static Response::Header deserialize(const std::vector<unsigned char> &data) {
                Header ret;
                uint64_t offset = 0;
                uint32_t type;
                offset += getNumeric(data, offset, type);
                ret.type = static_cast<Type >(type);
                offset += getNumeric(data, offset, ret.messageNumber);
                getNumeric(data, offset, ret.userId);
                return ret;
            }
        };

        Header header;
        std::vector<unsigned char> payload;

    };


}; // namespace helloworld
#endif //HELLOWORLD_REQUEST_H

