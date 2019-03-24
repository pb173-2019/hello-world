/**
 * @file requests.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Main file for request payload objects
 * @version 0.1
 * @date 2019-03-17
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_REQUESTS_H_
#define HELLOWORLD_SERVER_REQUESTS_H_

#include "../shared/serializable.h"

namespace helloworld {

struct RegisterRequest : public Serializable<RegisterRequest> {
    std::string sessionKey;
    std::string name;
    std::vector<unsigned char> publicKey;

    RegisterRequest() = default;

    RegisterRequest(std::string name, std::string sessionKey, std::vector<unsigned char> publicKey)
            : sessionKey(std::move(sessionKey)), name(std::move(name)), publicKey(std::move(publicKey)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, sessionKey);
        Serializable::addContainer<std::vector<unsigned char>>(result, publicKey);

        return result;
    }

    static RegisterRequest deserialize(const std::vector<unsigned char> &data) {
        RegisterRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.sessionKey);
        Serializable::getContainer<std::vector<unsigned char>>(data, position,
                                                               result.publicKey);
        return result;
    }
};

/**
 * Both registration & login have same second phase
 */
struct CompleteAuthRequest : public Serializable<CompleteAuthRequest> {
    std::vector<unsigned char> secret;
    std::string name;

    CompleteAuthRequest() = default;

    CompleteAuthRequest(std::vector<unsigned char> secret, std::string name)
            : secret(std::move(secret)), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::vector<unsigned char>>(result, secret);
        Serializable::addContainer<std::string>(result, name);

        return result;
    }

    static CompleteAuthRequest deserialize(const std::vector<unsigned char> &data) {
        CompleteAuthRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::vector<unsigned char>>(
                data, position, result.secret);
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);

        return result;
    }
};

struct AuthenticateRequest : public Serializable<AuthenticateRequest> {
    std::string sessionKey;
    std::string name;

    AuthenticateRequest() = default;

    AuthenticateRequest(std::string name, std::string sessionKey)
            : sessionKey(std::move(sessionKey)), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, sessionKey);
        return result;
    }

    static AuthenticateRequest deserialize(
            const std::vector<unsigned char> &data) {
        AuthenticateRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.sessionKey);
        return result;
    }
};

//todo maybe use user_data instead, but for now empty data serialization does not work properly
struct NameIdNeededRequest : public Serializable<AuthenticateRequest> {
    uint32_t id = 0;
    std::string name;

    NameIdNeededRequest() = default;

    NameIdNeededRequest(uint32_t id, std::string name)
            : id(id), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNumeric<uint32_t>(result, id);
        Serializable::addContainer<std::string>(result, name);
        return result;
    }

    static NameIdNeededRequest deserialize(
            const std::vector<unsigned char> &data) {
        NameIdNeededRequest result;
        uint64_t position = 0;
        position += Serializable::getNumeric<uint32_t>(data, position, result.id);
        position += Serializable::getContainer<std::string>(data, position, result.name);
        return result;
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_REQUESTS_H_
