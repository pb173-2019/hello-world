/**
 * @file requests.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Main file for request objects
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
    std::string name;
    std::string publicKey;

    RegisterRequest() = default;

    RegisterRequest(std::string name, std::string publicKey)
        : name(std::move(name)), publicKey(std::move(publicKey)) {}

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

struct CompleteRegistrationRequest
    : public Serializable<CompleteRegistrationRequest> {
    std::vector<unsigned char> secret;
    std::string name;

    CompleteRegistrationRequest() = default;

    CompleteRegistrationRequest(std::vector<unsigned char> secret,
                                std::string name)
        : secret(std::move(secret)), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::vector<unsigned char>>(result, secret);
        Serializable::addContainer<std::string>(result, name);

        return result;
    }

    static CompleteRegistrationRequest deserialize(
        const std::vector<unsigned char> &data) {
        CompleteRegistrationRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::vector<unsigned char>>(
            data, position, result.secret);
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);

        return result;
    }
};

struct AuthenticateRequest : public Serializable<AuthenticateRequest> {
    std::string name;

    AuthenticateRequest() = default;

    AuthenticateRequest(std::string name)
        : name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, name);

        return result;
    }

    static AuthenticateRequest deserialize(
        const std::vector<unsigned char> &data) {
        AuthenticateRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);

        return result;
    }
};

struct CompleteAuthenticationRequest
    : public Serializable<CompleteAuthenticationRequest> {
    std::vector<unsigned char> secret;
    std::string name;

    CompleteAuthenticationRequest() = default;

    CompleteAuthenticationRequest(std::vector<unsigned char> secret,
                                std::string name)
        : secret(std::move(secret)), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::vector<unsigned char>>(result, secret);
        Serializable::addContainer<std::string>(result, name);

        return result;
    }

    static CompleteAuthenticationRequest deserialize(
        const std::vector<unsigned char> &data) {
        CompleteAuthenticationRequest result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::vector<unsigned char>>(
            data, position, result.secret);
        position += Serializable::getContainer<std::string>(data, position,
                                                            result.name);

        return result;
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_REQUESTS_H_
