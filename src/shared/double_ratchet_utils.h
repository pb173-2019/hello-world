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

namespace helloworld {

using key = std::vector<unsigned char>;

struct Header : public Serializable<Header> {
    /**
     * @brief DH ratchet public key
     */
    key dh;
    /**
     * @brief previous chain length
     */
    size_t pn;
    /**
     * @brief message number
     */
    size_t n;

    Header() = default;

    Header(key dh, size_t pn, size_t n) : dh(std::move(dh)), pn(pn), n(n) {}

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

    static Header deserialize(const serialize::structure &data,
                              uint64_t &from) {
        Header result;
        result.dh = serialize::deserialize<decltype(result.dh)>(data, from);
        result.pn = serialize::deserialize<decltype(result.pn)>(data, from);
        result.n = serialize::deserialize<decltype(result.n)>(data, from);
        return result;
    }
    static Header deserialize(const serialize::structure &data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
};

struct CipherHMAC {
    key ciphertext;
    key hmac;
};

struct Message : public Serializable<Message> {
    Header header;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> hmac;

    Message() = default;

    Message(Header header, CipherHMAC cipherHMAC)
        : header(std::move(header)),
          ciphertext(cipherHMAC.ciphertext),
          hmac(cipherHMAC.hmac) {}

    serialize::structure &serialize(
        serialize::structure &result) const override {
        serialize::serialize(header.serialize(), result);
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
        message.header = serialize::deserialize<Header>(data, from);
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

struct DHPair {
    key pub;
    key priv;
};

class DoubleRatchetAdapter {
    static const size_t KDF_RK_SIZE = 64;
    hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE> _hmac;
    hkdf _hkdf_rk{std::make_unique<hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE>>(),
                  "KDF_RK for Double Ratchet. 584"};
    hkdf _hkdf_encrypt{
        std::make_unique<hmac_base<MBEDTLS_MD_SHA512, KDF_RK_SIZE>>(),
        "ENCRYPT for Double Ratchet. 239"};

    key getHmac(const key &authentication_key, const key &associated_data, const key &ciphertext) {
        auto hmacInput = associated_data;
        _hmac.setKey(to_hex(authentication_key));
        hmacInput.insert(hmacInput.end(), ciphertext.begin(), ciphertext.end());
        return _hmac.generate(hmacInput);
    }

   public:
    DHPair GENERATE_DH() const;

    key DH(const DHPair &dh_pair, const key &dh_pub) const;

    std::pair<key, key> KDF_RK(const key &rk, const key &dh_out);

    std::pair<key, key> KDF_CK(const key &ck, unsigned char input);

    CipherHMAC ENCRYPT(const key &mk, const key &plaintext,
                       const key &associated_data);

    std::vector<unsigned char> DECRYPT(const key &mk, const key &ciphertext,
                                       const key &hmac,
                                       const key &associated_data);

    Header HEADER(const DHPair &dh_pair, size_t pn, size_t n) const;

    std::vector<unsigned char> CONCAT(const key &ad, const Header &header) const;
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_UTILS_H_
