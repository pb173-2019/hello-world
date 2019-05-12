/**
 * @file client_utils.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Client utils for serialization
 * @version 0.1
 * @date 2019-05-12
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_CLIENT_UTILS_H_
#define HELLOWORLD_CLIENT_CLIENT_UTILS_H_

#include "../shared/X3DH.h"
#include "../shared/double_ratchet_utils.h"
#include "../shared/serializable.h"

namespace helloworld {

struct DRStatePair : Serializable<DRStatePair> {
    uint32_t id;
    DRState state;

    DRStatePair() = default;

    DRStatePair(uint32_t id, DRState state) : id(id), state(std::move(state)) {}

    serialize::structure& serialize(
        serialize::structure& result) const override {
        serialize::serialize(id, result);
        serialize::serialize(state, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static DRStatePair deserialize(const serialize::structure& data,
                                   uint64_t& from) {
        DRStatePair result;
        result.id = serialize::deserialize<decltype(result.id)>(data, from);
        result.state =
            serialize::deserialize<decltype(result.state)>(data, from);
        return result;
    }
    static DRStatePair deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct X3DHInitialMessage : Serializable<X3DHInitialMessage> {
    uint32_t id;
    X3DHRequest<C25519> message;

    X3DHInitialMessage() = default;

    X3DHInitialMessage(uint32_t id, X3DHRequest<C25519> message)
        : id(id), message(std::move(message)) {}

    serialize::structure& serialize(
        serialize::structure& result) const override {
        serialize::serialize(id, result);
        serialize::serialize(message, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static X3DHInitialMessage deserialize(const serialize::structure& data,
                                          uint64_t& from) {
        X3DHInitialMessage result;
        result.id = serialize::deserialize<decltype(result.id)>(data, from);
        result.message =
            serialize::deserialize<decltype(result.message)>(data, from);
        return result;
    }
    static X3DHInitialMessage deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct ClientState : Serializable<ClientState> {
    std::vector<DRStatePair> states;
    std::vector<X3DHInitialMessage> messages;

    ClientState() = default;

    serialize::structure& serialize(
        serialize::structure& result) const override {
        serialize::serialize(states, result);
        serialize::serialize(messages, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static ClientState deserialize(const serialize::structure& data,
                                   uint64_t& from) {
        ClientState result;
        result.states =
            serialize::deserialize<decltype(result.states)>(data, from);
        result.messages =
            serialize::deserialize<decltype(result.messages)>(data, from);
        return result;
    }
    static ClientState deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_CLIENT_CLIENT_UTILS_H_
