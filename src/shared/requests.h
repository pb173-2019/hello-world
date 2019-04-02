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

#include <ctime>
#include "serializable.h"

namespace helloworld {

    template <typename Asymmetric>
    struct KeyBundle : Serializable<KeyBundle<Asymmetric> > {
        static constexpr int key_len = Asymmetric::KEY_BYTES_LEN;
        static constexpr int signiture_len = Asymmetric::SIGN_BYTES_LEN;

        // can be changed to fixed storage container for length checking in the future
        using key_t = std::vector<unsigned char>;
        using signiture_t = std::vector<unsigned char>;

        std::time_t timestamp;
        key_t identityKey;
        key_t preKey;
        signiture_t preKeySingiture;
        std::vector<key_t > oneTimeKeys;

        void generateTimeStamp() {
            timestamp = std::time(nullptr);
        }

        std::vector<unsigned char> serialize() const override {
            std::vector<unsigned char> result;
            Serializable<KeyBundle<Asymmetric> >::addNumeric(result, timestamp);
            Serializable<KeyBundle<Asymmetric> >::addContainer(result, identityKey);
            Serializable<KeyBundle<Asymmetric> >::addContainer(result, preKey);
            Serializable<KeyBundle<Asymmetric> >::addContainer(result, preKeySingiture);
            Serializable<KeyBundle<Asymmetric> >::addNestedContainer(result, oneTimeKeys);
            return result;
        }

        static KeyBundle deserialize(const std::vector<unsigned char >& data) {
            KeyBundle result;
            uint64_t offset = 0;
            offset += Serializable<KeyBundle<Asymmetric> >::getNumeric(data, offset, result.timestamp);
            offset += Serializable<KeyBundle<Asymmetric> >::getContainer(data, offset, result.identityKey);
            offset += Serializable<KeyBundle<Asymmetric> >::getContainer(data, offset, result.preKey);
            offset += Serializable<KeyBundle<Asymmetric> >::getContainer(data, offset, result.preKeySingiture);
            offset += Serializable<KeyBundle<Asymmetric> >::getNestedContainer(data, offset, result.oneTimeKeys);
            return result;
        }
    };


struct AuthenticateRequest : public Serializable<AuthenticateRequest> {
    std::string sessionKey = ""; //session key filled on server side
    std::string name;
    std::vector<unsigned char> publicKey;

    AuthenticateRequest() = default;

    AuthenticateRequest(std::string name, std::vector<unsigned char> publicKey)
            : name(std::move(name)), publicKey(std::move(publicKey)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, sessionKey);
        Serializable::addContainer<std::vector<unsigned char>>(result, publicKey);

        return result;
    }

    static AuthenticateRequest deserialize(const std::vector<unsigned char> &data) {
        AuthenticateRequest result;
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

struct GenericRequest : public Serializable<AuthenticateRequest> {
    uint32_t id = 0;
    std::string name;

    GenericRequest() = default;

    GenericRequest(uint32_t id, std::string name) : id(id), name(std::move(name)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNumeric<uint32_t>(result, id);
        Serializable::addContainer<std::string>(result, name);
        return result;
    }

    static GenericRequest deserialize(
            const std::vector<unsigned char> &data) {
        GenericRequest result;
        uint64_t position = 0;
        position += Serializable::getNumeric<uint32_t>(data, position, result.id);
        position += Serializable::getContainer<std::string>(data, position, result.name);
        return result;
    }
};

struct GetUsers : public Serializable<GetUsers> {
    uint32_t id = 0;
    std::string name;
    std::string query;

    GetUsers() = default;

    GetUsers(uint32_t id, std::string name, std::string query) :
            id(id),
            name(std::move(name)),
            query(std::move(query)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNumeric<uint32_t>(result, id);
        Serializable::addContainer<std::string>(result, name);
        Serializable::addContainer<std::string>(result, query);
        return result;
    }

    static GetUsers deserialize(const std::vector<unsigned char> &data) {
        GetUsers result;
        uint64_t position = 0;
        position += Serializable::getNumeric<uint32_t>(data, position, result.id);
        position += Serializable::getContainer<std::string>(data, position, result.name);
        position += Serializable::getContainer<std::string>(data, position, result.query);
        return result;
    }
};

struct SendData : public Serializable<SendData> {
    std::string from;
    std::vector<unsigned char> data;

    SendData() = default;

    SendData(std::string from, std::vector<unsigned char> data) :
            from(std::move(from)), data(std::move(data)) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer<std::string>(result, from);
        Serializable::addContainer<std::vector<unsigned char>>(result, data);
        return result;
    }

    static SendData deserialize(const std::vector<unsigned char> &data) {
        SendData result;
        uint64_t position = 0;
        position += Serializable::getContainer<std::string>(data, position, result.from);
        position += Serializable::getContainer<std::vector<unsigned char>>(data, position, result.data);
        return result;
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_REQUESTS_H_
