#include "double_ratchet_utils.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

std::vector<unsigned char> DoubleRatchetAdapter::to_vector(std::istream &in,
                                                           size_t size) {
    std::vector<unsigned char> result(size);
    size_t read = read_n(in, result.data(), size);
    if (read != size) {
        throw Error("DR: Could not read AEAD encrypted stream.");
    }
    return result;
}

DHPair DoubleRatchetAdapter::GENERATE_DH() const {
    C25519KeyGen c25519generator;
    return {c25519generator.getPublicKey(), c25519generator.getPrivateKey()};
}

key DoubleRatchetAdapter::DH(const DHPair &dh_pair, const key &dh_pub) {
    C25519 c25519;
    c25519.setPrivateKey(dh_pair.priv);
    c25519.setPublicKey(dh_pub);
    return c25519.getShared();
}

std::pair<key, key> DoubleRatchetAdapter::KDF_RK(const key &rk,
                                                 const key &dh_out) {
    _hkdf_rk.setSalt(to_hex(rk));
    return split(from_hex(_hkdf_rk.generate(to_hex(dh_out), KDF_RK_SIZE)));
}

std::pair<key, key> DoubleRatchetAdapter::KDF_CK(const key &ck,
                                                 unsigned char input) {
    _hmac.setKey(to_hex(ck));
    return split(_hmac.generate({input}));
}

CipherHMAC DoubleRatchetAdapter::ENCRYPT(const key &mk, const key &plaintext,
                                         const key &associated_data) {
    auto keys = from_hex(_hkdf_encrypt.generate(to_hex(mk), 60));
    key encryptionKey, authenticationKey, iv;
    std::tie(encryptionKey, keys) = split(keys, 16);
    std::tie(authenticationKey, iv) = split(keys, 32);
    assert(iv.size() == 12);

    AESGCM gcm;
    gcm.setKey(to_hex(encryptionKey));
    gcm.setIv(to_hex(iv));
    std::vector<unsigned char> ciphertext;
    gcm.encryptWithAd(plaintext, associated_data, ciphertext);

    auto hmacInput = associated_data;
    hmacInput.insert(hmacInput.end(), ciphertext.begin(), ciphertext.end());

    return {ciphertext, _hmac.generate(hmacInput)};
}

std::vector<unsigned char> DoubleRatchetAdapter::DECRYPT(
    const key &mk, const key &ciphertext, const key &associated_data) {
    std::vector<unsigned char> keys =
        from_hex(_hkdf_encrypt.generate(to_hex(mk), 60));
    key encryptionKey, authenticationKey, iv;
    std::tie(encryptionKey, keys) = split(keys, 16);
    std::tie(authenticationKey, iv) = split(keys, 32);
    assert(iv.size() == 12);

    AESGCM gcm;
    gcm.setKey(to_hex(encryptionKey));
    gcm.setIv(to_hex(iv));

    std::vector<unsigned char> plaintext;
    gcm.decryptWithAd(ciphertext, associated_data, plaintext);

    // todo check hmac
    return plaintext;
}

Header DoubleRatchetAdapter::HEADER(const DHPair &dh_pair, size_t pn,
                                    size_t n) {
    return Header(dh_pair.pub, pn, n);
}

std::vector<unsigned char> DoubleRatchetAdapter::CONCAT(const key &ad,
                                                        const Header &header) {
    auto result = ad;
    auto serializedHeader = header.serialize();
    result.insert(result.end(), serializedHeader.begin(),
                  serializedHeader.end());

    return result;
}

}    // namespace helloworld
