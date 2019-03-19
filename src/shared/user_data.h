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

struct UserData : Serializable<UserData> {
    uint32_t _id = 0;
    std::string _name;
    std::string _publicKey;

    UserData() = default;

    UserData(uint32_t id, std::string name, std::string pubKey) :
            _id(id),
            _name(std::move(name)),
            _publicKey(std::move(pubKey)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNumeric<uint32_t>(result, _id);
        Serializable::addContainer<std::string>(result, _name);
        Serializable::addContainer<std::string>(result, _publicKey);
        return result;
    }

    static UserData deserialize(const std::vector<unsigned char>& data) {
        UserData userData;
        uint64_t position = 0;
        position += Serializable::getNumeric<uint32_t>(data, 0, userData._id);
        position += Serializable::getContainer<std::string>(data, position, userData._name);
        Serializable::getContainer<std::string>(data, position, userData._publicKey);
        return userData;
    }
};

}

#endif //HELLOWORLD_SHARED_CLIENT_INFO_H_
