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

#include "serializable.h"

namespace helloworld {

struct UserListReponse : public Serializable<UserListReponse> {
    std::vector<std::string> online;

    UserListReponse() = default;

    explicit UserListReponse(std::vector<std::string> users) : online(std::move(users)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNestedContainer<std::vector<std::string>, std::string>(result, online);
        return result;
    }

    static UserListReponse deserialize(const std::vector<unsigned char> &data) {
        UserListReponse result;
        Serializable::getNestedContainer<std::vector<std::string>, std::string>(data, 0, result.online);
        return result;
    }
};



}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_RESPONSES_H_
