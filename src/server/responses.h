#include <utility>

/**
 * @file responses.h
 * @author Jiří Horák (469130@fi.muni.cz)
 * @brief Main file for response payload objects
 * @version 0.1
 * @date 2019-03-22
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_RESPONSES_H_
#define HELLOWORLD_SERVER_RESPONSES_H_

#include "../shared/serializable.h"

namespace helloworld {

struct OnlineUsersResponse : public Serializable<OnlineUsersResponse> {
    std::vector<std::string> online;

    OnlineUsersResponse() = default;

    explicit OnlineUsersResponse(std::vector<std::string> users) : online(std::move(users)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNestedContainer<std::vector<std::string>, std::string>(result, online);
        return result;
    }

    static OnlineUsersResponse deserialize(const std::vector<unsigned char> &data) {
        OnlineUsersResponse result;
        Serializable::getNestedContainer<std::vector<std::string>, std::string>(data, 0, result.online);
        return result;
    }
};



}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_RESPONSES_H_
