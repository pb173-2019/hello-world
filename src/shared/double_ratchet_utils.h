/**
 * @file double_ratchet_utils.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Double ratchet helper classes
 * @version 0.1
 * @date 2019-04-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_DOUBLE_RATCHET_UTILS_H_
#define HELLOWORLD_SHARED_DOUBLE_RATCHET_UTILS_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "aes_gcm.h"
#include "curve_25519.h"
#include "hkdf.h"
#include "hmac.h"
#include "hmac_base.h"
#include "serializable.h"

namespace helloworld {

struct DHPair : Serializable<DHPair> {
    zero::bytes_t pub;
    zero::bytes_t priv;

    DHPair() = default;

    DHPair(zero::bytes_t pub, zero::bytes_t priv)
        : pub(std::move(pub)), priv(std::move(priv)) {}

    serialize::structure &serialize(
        serialize::structure &result) const override {
        serialize::serialize(pub, result);
        serialize::serialize(priv, result);
        return result;
    }

    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static DHPair deserialize(const serialize::structure &data,
                              uint64_t &from) {
        DHPair object;
        object.pub = serialize::deserialize<decltype(object.pub)>(data, from);
        object.priv = serialize::deserialize<decltype(object.priv)>(data, from);
        return object;
    }

    static DHPair deserialize(const serialize::structure &data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct DRState : Serializable<DRState> {
    DHPair DHs;    // DH Ratchet key pair (the “sending” or “self” ratchet key)
    zero::bytes_t
        DHr;    // DH Ratchet public key (the “received” or “remote” key)
    zero::bytes_t RK;          // 32-byte Root Key
    zero::bytes_t CKs, CKr;    // 32-byte Chain Keys for sending and receiving
    size_t Ns, Nr;             // Message numbers for sending and receiving
    size_t PN;                 // Number of messages in previous sending chain
    std::map<std::pair<zero::bytes_t, size_t>, zero::bytes_t> MKSKIPPED;
    // Dictionary of skipped-over message keys, indexed
    // by ratchet public key and message number. Raises an
    // exception if too many elements are stored
    zero::bytes_t AD;        // additional data from X3DH
    bool receivedMessage;    // boolean flag for checking whether double ratchet
                             // was initialized on both sides

    serialize::structure &serialize(
        serialize::structure &result) const override {
        serialize::serialize(DHs, result);
        serialize::serialize(DHr, result);
        serialize::serialize(RK, result);
        serialize::serialize(CKs, result);
        serialize::serialize(CKr, result);
        serialize::serialize(Ns, result);
        serialize::serialize(Nr, result);
        serialize::serialize(PN, result);
        uint64_t size = MKSKIPPED.size();
        serialize::serialize(size, result);
        for (const auto &x : MKSKIPPED) {
            serialize::serialize(x.first.first, result);
            serialize::serialize(x.first.second, result);
            serialize::serialize(x.second, result);
        }
        serialize::serialize(AD, result);
        serialize::serialize(receivedMessage, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static DRState deserialize(const serialize::structure &data,
                               uint64_t &from) {
        DRState result;
        result.DHs = serialize::deserialize<decltype(result.DHs)>(data, from);
        result.DHr = serialize::deserialize<decltype(result.DHr)>(data, from);
        result.RK = serialize::deserialize<decltype(result.RK)>(data, from);
        result.CKs = serialize::deserialize<decltype(result.CKs)>(data, from);
        result.CKr = serialize::deserialize<decltype(result.CKr)>(data, from);
        result.Ns = serialize::deserialize<decltype(result.Ns)>(data, from);
        result.Nr = serialize::deserialize<decltype(result.Nr)>(data, from);
        result.PN = serialize::deserialize<decltype(result.PN)>(data, from);
        uint64_t size = serialize::deserialize<uint64_t>(data, from);
        for (uint64_t i = 0; i < size; ++i) {
            std::pair<zero::bytes_t, size_t> skipped_key;
            skipped_key.first =
                serialize::deserialize<zero::bytes_t>(data, from);
            skipped_key.second = serialize::deserialize<size_t>(data, from);
            auto value = serialize::deserialize<zero::bytes_t>(data, from);

            result.MKSKIPPED.emplace(std::move(skipped_key), std::move(value));
        }
        result.AD = serialize::deserialize<decltype(result.AD)>(data, from);
        result.receivedMessage = serialize::deserialize<decltype(result.receivedMessage)>(data, from);
        return result;
    }

    static DRState deserialize(const serialize::structure &data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct MessageHeader : public Serializable<MessageHeader> {
    /**
     * @brief DH ratchet public key
     */
    zero::bytes_t dh;
    /**
     * @brief previous chain length
     */
    size_t pn;
    /**
     * @brief message number
     */
    size_t n;

    MessageHeader() = default;

    MessageHeader(zero::bytes_t dh, size_t pn, size_t n)
        : dh(std::move(dh)), pn(pn), n(n) {}

    serialize::structure &serialize(
        serialize::structure &result) const override {
        serialize::serialize(dh, result);
        serialize::serialize(pn, result);
        serialize::serialize(n, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static MessageHeader deserialize(const serialize::structure &data,
                                     uint64_t &from) {
        MessageHeader result;
        result.dh = serialize::deserialize<decltype(result.dh)>(data, from);
        result.pn = serialize::deserialize<decltype(result.pn)>(data, from);
        result.n = serialize::deserialize<decltype(result.n)>(data, from);
        return result;
    }
    static MessageHeader deserialize(const serialize::structure &data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct CipherHMAC {
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> hmac;
};

struct Message : public Serializable<Message> {
    MessageHeader header;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> hmac;

    Message() = default;

    Message(MessageHeader header, const CipherHMAC &cipherHMAC)
        : header(std::move(header)),
          ciphertext(cipherHMAC.ciphertext),
          hmac(cipherHMAC.hmac) {}

    serialize::structure &serialize(
        serialize::structure &result) const override {
        serialize::serialize(header, result);
        serialize::serialize(ciphertext, result);
        serialize::serialize(hmac, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static Message deserialize(const serialize::structure &data,
                               uint64_t &from) {
        Message message;
        message.header =
            serialize::deserialize<decltype(message.header)>(data, from);
        message.ciphertext =
            serialize::deserialize<decltype(message.ciphertext)>(data, from);
        message.hmac =
            serialize::deserialize<decltype(message.hmac)>(data, from);
        return message;
    }
    static Message deserialize(const serialize::structure &data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

class DoubleRatchetAdapter {
    static const size_t KDF_RK_SIZE = 64;
    hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE> _hmac;
    hkdf _hkdf_rk{std::make_unique<hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE>>(),
                  "KDF_RK for Double Ratchet. 584"};
    hkdf _hkdf_encrypt{
        std::make_unique<hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE>>(),
        "ENCRYPT for Double Ratchet. 239"};

    std::vector<unsigned char> getHmac(
        const zero::bytes_t &authentication_key,
        const std::vector<unsigned char> &associated_data,
        const std::vector<unsigned char> &ciphertext) {
        auto hmacInput = associated_data;
        _hmac.setKey(authentication_key);
        hmacInput.insert(hmacInput.end(), ciphertext.begin(), ciphertext.end());
        return _hmac.generate(hmacInput);
    }

   public:
    DHPair GENERATE_DH() const;

    zero::bytes_t DH(const DHPair &dh_pair, const zero::bytes_t &dh_pub) const;

    std::pair<zero::bytes_t, zero::bytes_t> KDF_RK(const zero::bytes_t &rk,
                                                   const zero::bytes_t &dh_out);

    std::pair<zero::bytes_t, zero::bytes_t> KDF_CK(const zero::bytes_t &ck,
                                                   unsigned char input);

    CipherHMAC ENCRYPT(const zero::bytes_t &mk,
                       const std::vector<unsigned char> &plaintext,
                       const std::vector<unsigned char> &associated_data);

    std::vector<unsigned char> DECRYPT(
        const zero::bytes_t &mk, const std::vector<unsigned char> &ciphertext,
        const std::vector<unsigned char> &hmac,
        const std::vector<unsigned char> &associated_data);

    MessageHeader HEADER(const DHPair &dh_pair, size_t pn, size_t n) const;

    std::vector<unsigned char> CONCAT(const zero::bytes_t &ad,
                                      const MessageHeader &header) const;
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_UTILS_H_
