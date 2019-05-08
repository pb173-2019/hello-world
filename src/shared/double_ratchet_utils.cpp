#include "double_ratchet_utils.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DHPair DoubleRatchetAdapter::GENERATE_DH() const {
    C25519KeyGen c25519generator;
    return {c25519generator.getPublicKey(), c25519generator.getPrivateKey()};
}

zero::bytes_t DoubleRatchetAdapter::DH(const DHPair &dh_pair, const zero::bytes_t &dh_pub) const {
    C25519 c25519;
    c25519.setPrivateKey(dh_pair.priv);
    c25519.setPublicKey(dh_pub);
    return c25519.getShared();
}

std::pair<zero::bytes_t, zero::bytes_t> DoubleRatchetAdapter::KDF_RK(const zero::bytes_t &rk, const zero::bytes_t &dh_out) {
    _hkdf_rk.setSalt(to_hex(rk));
    return split(from_hex(_hkdf_rk.generate(to_hex(dh_out), KDF_RK_SIZE)));
}

std::pair<zero::bytes_t, zero::bytes_t> DoubleRatchetAdapter::KDF_CK(const zero::bytes_t &ck,
                                                 unsigned char input) {
    _hmac.setKey(to_hex(ck));
    return split(_hmac.generate(zero::bytes_t{input}));
}

CipherHMAC DoubleRatchetAdapter::ENCRYPT(const zero::bytes_t &mk, const std::vector<unsigned char> &plaintext,
                                         const std::vector<unsigned char> &associated_data) {
    zero::bytes_t keys = from_hex(_hkdf_encrypt.generate(to_hex(mk), 60));
    zero::bytes_t encryptionKey, authenticationKey, iv;
    std::tie(encryptionKey, keys) = split(keys, 16);
    std::tie(authenticationKey, iv) = split(keys, 32);

    AESGCM gcm;
    gcm.setKey(to_hex(encryptionKey));
    gcm.setIv(to_hex(iv));
    std::vector<unsigned char> ciphertext;
    gcm.encryptWithAd(plaintext, associated_data, ciphertext);

    return {ciphertext, getHmac(authenticationKey, associated_data, ciphertext)};
}

std::vector<unsigned char> DoubleRatchetAdapter::DECRYPT(
    const zero::bytes_t &mk, const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &hmac,
    const std::vector<unsigned char> &associated_data) {

    zero::bytes_t keys =
        from_hex(_hkdf_encrypt.generate(to_hex(mk), 60));
    zero::bytes_t encryptionKey, authenticationKey, iv;

    std::tie(encryptionKey, keys) = split(keys, 16);
    std::tie(authenticationKey, iv) = split(keys, 32);

    if (getHmac(authenticationKey, associated_data, ciphertext) != hmac) {
        throw Error("DR: authentication failed");
    }

    AESGCM gcm;
    gcm.setKey(to_hex(encryptionKey));
    gcm.setIv(to_hex(iv));

    std::vector<unsigned char> plaintext;
    gcm.decryptWithAd(ciphertext, associated_data, plaintext);

    return plaintext;
}

MessageHeader DoubleRatchetAdapter::HEADER(const DHPair &dh_pair, size_t pn,
                                    size_t n) const {
    return MessageHeader(dh_pair.pub, pn, n);
}

std::vector<unsigned char> DoubleRatchetAdapter::CONCAT(
    const zero::bytes_t &ad, const MessageHeader &header) const {

    std::vector<unsigned char> result;
    result.insert(result.begin(), ad.begin(), ad.end());
    auto serializedMessageHeader = header.serialize();
    result.insert(result.end(), serializedMessageHeader.begin(),
                  serializedMessageHeader.end());
    return result;
}

}    // namespace helloworld
