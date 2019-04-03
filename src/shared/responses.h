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
    std::vector<uint32_t> ids;
    std::vector<std::string> online;

    UserListReponse() = default;

    UserListReponse(std::vector<std::string> users, std::vector<uint32_t> ids) :
            ids(std::move(ids)), online(std::move(users)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::vector<uint32_t >>(result, ids);
        Serializable::addNestedContainer<std::vector<std::string>, std::string>(result, online);
        return result;
    }

    static UserListReponse deserialize(const std::vector<unsigned char> &data) {
        UserListReponse result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::vector<uint32_t >>(data, position, result.ids);
        position += Serializable::getNestedContainer<std::vector<std::string>, std::string>(data, position, result.online);
        return result;
    }
};


}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_RESPONSES_H_
