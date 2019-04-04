/**
 * @file serializable_error.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Custom exception for errors returned by server
 * @version 0.1
 * @date 2019-03-17
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_ERROR_H_
#define HELLOWORLD_SHARED_ERROR_H_

#include <exception>
#include <iostream>

#include "serializable.h"

namespace helloworld {

struct Error : public std::exception, public Serializable<Error> {
    std::string message;

    Error() = default;

    explicit Error(std::string message) : message(std::move(message)) {}

    const char *what() const noexcept override { return message.c_str(); }

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(message, result);
        return result;
    }
    serialize::structure serialize() const {
        serialize::structure result;
        return serialize(result);
    }

    static Error deserialize(const serialize::structure  &data, uint64_t& from) {
        Error result;
        result.message =
                serialize::deserialize<decltype(result.message)>(data, from);
        return result;
    }
    static Error deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

} // namespace helloworld

#endif // HELLOWORLD_SHARED_ERROR_H_
