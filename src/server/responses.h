/**
 * @file responses.h
 * @author Jiří Horák (xivora@fi.muni.cz)
 * @brief Main file for request objects
 * @version 0.1
 * @date 2019-03-17
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_RESPONSES_H_
#define HELLOWORLD_SERVER_RESPONSES_H_

#include <map>

#include "../shared/serializable.h"

namespace helloworld {

struct OnlineUsersResponse : public Serializable<OnlineUsersResponse> {
    std::map<std::string> online;

    RegisterRequest() = default;

    RegisterRequest(const std::map<std::string>& users) : online(users) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, publicKey);

        return result;
    }

    static RegisterRequest deserialize(const std::vector<unsigned char> &data) {
        RegisterRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);
        Serializable::getContainer<std::string>(data, position,
                                                result.publicKey);

        return result;
    }
};



}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_RESPONSES_H_
