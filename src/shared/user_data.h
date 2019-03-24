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

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNumeric<uint32_t>(result, id);
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, sessionKey);
        Serializable::addContainer<std::vector<unsigned char>>(result, publicKey);
        return result;
    }

    static UserData deserialize(const std::vector<unsigned char>& data) {
        UserData userData;
        uint64_t position = 0;
        position += Serializable::getNumeric<uint32_t>(data, 0, userData.id);
        position += Serializable::getContainer<std::string>(data, position, userData.name);
        position += Serializable::getContainer<std::string>(data, position, userData.sessionKey);
        Serializable::getContainer<std::vector<unsigned char>>(data, position, userData.publicKey);
        return userData;
    }
};

}

#endif //HELLOWORLD_SHARED_CLIENT_INFO_H_
