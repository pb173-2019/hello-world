/**
 * @file client_info.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Client info structure to hold user data
 * @version 0.1
 * @date 16. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_CLIENT_INFO_H_
#define HELLOWORLD_SHARED_CLIENT_INFO_H_

#include <string>
#include <iostream>

#include "serializable.h"

namespace helloworld {

struct UserData : public Serializable<UserData> {
    uint32_t id = 0;
    std::string name;
    std::string sessionKey;
    std::vector<unsigned char> publicKey;

    UserData() = default;

    UserData(uint32_t id, std::string name, std::string sessionKey, std::vector<unsigned char> publicKey) :
             id(id),
             name(std::move(name)),
             sessionKey(std::move(sessionKey)),
             publicKey(std::move(publicKey)) {}

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(id, result);
        serialize::serialize(name, result);
        serialize::serialize(sessionKey, result);
        serialize::serialize(publicKey, result);

        return result;
    }
    serialize::structure serialize() const {
        serialize::structure result;
        return serialize(result);
    }

    static UserData deserialize(const serialize::structure  &data, uint64_t& from) {
        UserData userData;
        userData.id =
                serialize::deserialize<decltype(userData.id)>(data, from);
        userData.name =
                serialize::deserialize<decltype(userData.name)>(data, from);
        userData.sessionKey =
                serialize::deserialize<decltype(userData.sessionKey)>(data, from);
        userData.publicKey =
                serialize::deserialize<decltype(userData.publicKey)>(data, from);
        return userData;
    }
    static UserData deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

}

#endif //HELLOWORLD_SHARED_CLIENT_INFO_H_
