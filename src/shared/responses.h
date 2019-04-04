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

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(ids, result);
        serialize::serialize(online, result);
        return result;
    }
    serialize::structure serialize() const {
        serialize::structure result;
        return serialize(result);
    }

    static UserListReponse deserialize(const serialize::structure  &data, uint64_t& from) {
        UserListReponse result;
        result.ids =
                serialize::deserialize<decltype(result.ids)>(data, from);
        result.online =
                serialize::deserialize<decltype(result.online)>(data, from);
        return result;
    }
    static UserListReponse deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};


}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_RESPONSES_H_
