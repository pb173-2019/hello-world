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
#include "utils.h"
#include "serializable.h"

namespace helloworld {

template<typename Asymmetric>
struct KeyBundle : Serializable<KeyBundle<Asymmetric> > {
    static constexpr int key_len = Asymmetric::KEY_BYTES_LEN;
    static constexpr int signiture_len = Asymmetric::SIGN_BYTES_LEN;

    // can be changed to fixed storage container for length checking in the future
    using key_t = std::vector<unsigned char>;
    using signiture_t = std::vector<unsigned char>;

    uint64_t timestamp;
    key_t identityKey;
    key_t preKey;
    signiture_t preKeySingiture;
    std::vector<key_t> oneTimeKeys;

    void generateTimeStamp() {
        timestamp = getTimestampOf(nullptr);
    }

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(timestamp, result);
        serialize::serialize(identityKey, result);
        serialize::serialize(preKey, result);
        serialize::serialize(preKeySingiture, result);
        serialize::serialize(oneTimeKeys, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static KeyBundle deserialize(const serialize::structure  &data, uint64_t& from) {
        KeyBundle result;
        result.timestamp =
                serialize::deserialize<decltype(result.timestamp)>(data, from);
        result.identityKey =
                serialize::deserialize<decltype(result.identityKey)>(data, from);
        result.preKey =
                serialize::deserialize<decltype(result.preKey)>(data, from);
        result.preKeySingiture =
                serialize::deserialize<decltype(result.preKeySingiture)>(data, from);
        result.oneTimeKeys =
                serialize::deserialize<decltype(result.oneTimeKeys)>(data, from);
        return result;
    }
    static KeyBundle deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }

};


struct AuthenticateRequest : public Serializable<AuthenticateRequest> {
    std::string sessionKey = ""; //session key filled on server side
    std::string name;
    std::vector<unsigned char> publicKey;

    AuthenticateRequest() = default;

    AuthenticateRequest(std::string name, std::vector<unsigned char> publicKey)
            : name(std::move(name)), publicKey(std::move(publicKey)) {}

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(name, result);
        serialize::serialize(sessionKey, result);
        serialize::serialize(publicKey, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static AuthenticateRequest deserialize(const serialize::structure  &data, uint64_t& from) {
        AuthenticateRequest result;
        result.name =
                serialize::deserialize<decltype(result.name)>(data, from);
        result.sessionKey =
                serialize::deserialize<decltype(result.sessionKey)>(data, from);
        result.publicKey =
                serialize::deserialize<decltype(result.publicKey)>(data, from);
        return result;
    }
    static AuthenticateRequest deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
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

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(secret, result);
        serialize::serialize(name, result);

        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static CompleteAuthRequest deserialize(const serialize::structure &data, uint64_t& from) {
        CompleteAuthRequest result;
        result.secret = serialize::deserialize<std::vector<unsigned char>>(data, from);
        result.name = serialize::deserialize<std::string>(data, from);
        return result;
    }

    static CompleteAuthRequest deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }

};

struct GenericRequest : public Serializable<AuthenticateRequest> {
    uint32_t id = 0;
    std::string name;

    GenericRequest() = default;

    GenericRequest(uint32_t id, std::string name) : id(id), name(std::move(name)) {}

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(id, result);
        serialize::serialize(name, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static GenericRequest deserialize(const serialize::structure &data, uint64_t& from) {
        GenericRequest result;
        result.id = serialize::deserialize<uint32_t>(data, from);
        result.name = serialize::deserialize<std::string>(data, from);
        return result;
    }

    static GenericRequest deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
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

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(id, result);
        serialize::serialize(name, result);
        serialize::serialize(query, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static GetUsers deserialize(const serialize::structure &data, uint64_t& from) {
        GetUsers result;

        result.id = serialize::deserialize<uint32_t>(data, from);
        result.name = serialize::deserialize<std::string>(data, from);
        result.query = serialize::deserialize<std::string>(data, from);
        return result;
    }
    static GetUsers deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct SendData : public Serializable<SendData> {
    std::string date;
    std::string from;
    uint32_t fromId;
    std::vector<unsigned char> data;

    SendData() = default;

    SendData(std::string date, std::string from, uint32_t fromId, std::vector<unsigned char> data) :
            date(std::move(date)), from(std::move(from)), fromId(fromId), data(std::move(data)) {}

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(date, result);
        serialize::serialize(from, result);
        serialize::serialize(fromId, result);
        serialize::serialize(data, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static SendData deserialize(const serialize::structure &data, uint64_t& from) {
        SendData result;
        result.date = serialize::deserialize<std::string>(data, from);
        result.from = serialize::deserialize<std::string>(data, from);
        result.fromId = serialize::deserialize<decltype(result.fromId)>(data, from);
        result.data = serialize::deserialize<decltype(result.data)>(data, from);

        return result;
    }

    static SendData deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

template<typename Asymmetric>
struct X3DHRequest : public Serializable<X3DHRequest<Asymmetric>> {
    using key_t = typename KeyBundle<Asymmetric>::key_t;

    static constexpr unsigned char OP_KEY_NONE = 0x00;
    static constexpr unsigned char OP_KEY_USED = 0x01;

    uint64_t timestamp;

    key_t senderIdPubKey;
    key_t senderEphermalPubKey;
    unsigned char opKeyUsed = OP_KEY_NONE;
    size_t opKeyId;
    std::vector<unsigned char> AEADenrypted;

    X3DHRequest() = default;

    serialize::structure& serialize(serialize::structure& result) const override {
        serialize::serialize(timestamp, result);
        serialize::serialize(senderIdPubKey, result);
        serialize::serialize(senderEphermalPubKey, result);
        serialize::serialize(opKeyUsed, result);
        serialize::serialize(opKeyId, result);
        serialize::serialize(AEADenrypted, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static X3DHRequest deserialize(const serialize::structure &data, uint64_t& from) {
        X3DHRequest result;
        result.timestamp =
                serialize::deserialize<decltype(result.timestamp)>(data, from);
        result.senderIdPubKey =
                serialize::deserialize<decltype(result.senderIdPubKey)>(data, from);
        result.senderEphermalPubKey =
                serialize::deserialize<decltype(result.senderEphermalPubKey)>(data, from);
        result.opKeyUsed =
                serialize::deserialize<decltype(result.opKeyUsed)>(data, from);
        result.opKeyId =
                serialize::deserialize<decltype(result.opKeyId)>(data, from);
        result.AEADenrypted =
                serialize::deserialize<decltype(result.AEADenrypted)>(data, from);
        return result;
    }
    static X3DHRequest deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_REQUESTS_H_
