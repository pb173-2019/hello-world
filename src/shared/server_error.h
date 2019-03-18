/**
 * @file server_error.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Custom exception for errors returned by server
 * @version 0.1
 * @date 2019-03-17
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_SERVERROR_H_
#define HELLOWORLD_SHARED_SERVERROR_H_

#include <exception>
#include <iostream>

#include "serializable.h"

namespace helloworld {

struct ServerError : public std::exception, public Serializable<ServerError> {
    std::string message;

    ServerError() = default;

    explicit ServerError(std::string message) : message(std::move(message)) {}

    const char *what() const throw() override { return message.c_str(); }

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, message);

        return result;
    }

    static ServerError deserialize(const std::vector<unsigned char> &data) {
        ServerError result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.message);

        return result;
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_SERVERROR_H_
