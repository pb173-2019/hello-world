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
    key dh;
    size_t pn;
    size_t n;

    Header() = default;

    Header(key dh, size_t pn, size_t n) : dh(std::move(dh)), pn(pn), n(n) {}

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer(result, dh);
        Serializable::addNumeric(result, pn);
        Serializable::addNumeric(result, n);
        return result;
    }

    static Header deserialize(const key &data) {
        Header header;
        uint64_t position = 0;
        position += Serializable::getContainer(data, position, header.dh);
        position += Serializable::getNumeric(data, position, header.pn);
        position += Serializable::getNumeric(data, position, header.n);
        return header;
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

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addContainer(result, header.serialize());
        Serializable::addContainer(result, ciphertext);
        Serializable::addContainer(result, hmac);
        return result;
    }

    static Message deserialize(const key &data) {
        Message message;
        uint64_t position = 0;
        std::vector<unsigned char> serialized;
        position += Serializable::getContainer(data, position, serialized);
        message.header = Header::deserialize(serialized);
        position +=
            Serializable::getContainer(data, position, message.ciphertext);
        position += Serializable::getContainer(data, position, message.hmac);
        return message;
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

    std::vector<unsigned char> to_vector(std::istream &in, size_t size);

   public:
    DHPair GENERATE_DH() const;

    key DH(const DHPair &dh_pair, const key &dh_pub);

    std::pair<key, key> KDF_RK(const key &rk, const key &dh_out);

    std::pair<key, key> KDF_CK(const key &ck, unsigned char input);

    CipherHMAC ENCRYPT(const key &mk, const key &plaintext,
                       const key &associated_data);

    std::vector<unsigned char> DECRYPT(const key &mk, const key &ciphertext,
                                       const key &associated_data);

    Header HEADER(const DHPair &dh_pair, size_t pn, size_t n);

    std::vector<unsigned char> CONCAT(const key &ad, const Header &header);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_UTILS_H_
