#include "double_ratchet.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DoubleRatchet::DoubleRatchet(const std::vector<unsigned char> &SK,
                             std::vector<unsigned char> other_dh_public_key)
    : _DHs(ext.GENERATE_DH()),
      _DHr(std::move(other_dh_public_key)),
      _CKr({}),
      _Ns(0),
      _Nr(0),
      _PN(0),
      _MKSKIPPED({}) {
    std::tie(_RK, _CKs) = ext.KDF_RK(SK, ext.DH(_DHs, _DHr));
}

DoubleRatchet::DoubleRatchet(std::vector<unsigned char> SK,
                             std::vector<unsigned char> dh_public_key,
                             std::vector<unsigned char> dh_private_key)
    : _DHs({std::move(dh_public_key), std::move(dh_private_key)}),
      _DHr({}),
      _RK(std::move(SK)),
      _CKs({}),
      _CKr({}),
      _Ns(0),
      _Nr(0),
      _PN(0),
      _MKSKIPPED({}) {}

Message DoubleRatchet::RatchetEncrypt(
    const std::vector<unsigned char> &plaintext,
    const std::vector<unsigned char> &AD) {
    key mk;
    std::tie(_CKs, mk) = ext.KDF_CK(_CKs, 0x01);
    Header header = ext.HEADER(_DHs, _PN, _Ns);
    ++_Ns;

    return Message(header, ext.ENCRYPT(mk, plaintext, ext.CONCAT(AD, header)));
}

std::vector<unsigned char> DoubleRatchet::RatchetDecrypt(
    const Message &message, const std::vector<unsigned char> &AD) {
    auto header = message.header;
    auto ciphertext = message.ciphertext;
    auto hmac = message.hmac;

    key plaintext = TrySkippedMessageKeys(header, ciphertext, AD);
    if (!plaintext.empty()) {
        return plaintext;
    }

    if (header.dh != _DHr) {
        SkipMessageKeys(header.pn);
        DHRatchet(header);
    }

    SkipMessageKeys(header.n);
    key mk;
    std::tie(_CKr, mk) = ext.KDF_CK(_CKr, 0x01); // TODO magic constant
    ++_Nr;

    return ext.DECRYPT(mk, ciphertext, ext.CONCAT(AD, header));
}

key DoubleRatchet::TrySkippedMessageKeys(const Header &header,
                                         const key &ciphertext, const key &AD) {
    auto found = _MKSKIPPED.find({header.dh, header.n});
    if (found == _MKSKIPPED.end()) {
        return {};
    }

    key mk = found->second;
    _MKSKIPPED.erase(found);

    return ext.DECRYPT(mk, ciphertext, ext.CONCAT(AD, header));
}

void DoubleRatchet::SkipMessageKeys(size_t until) {
    if (_Nr + MAX_SKIP < until) {
        throw std::runtime_error(
            "skipped more than MAX_SKIP messages in double ratchet");
    }

    if (!_CKr.empty()) {
        while (_Nr < until) {
            key mk;
            std::tie(_CKr, mk) = ext.KDF_CK(_CKr, 0x01);
            _MKSKIPPED.emplace(std::make_pair(_DHr, _Nr), mk);
            ++_Nr;
        }
    }
}

void DoubleRatchet::DHRatchet(const Header &header) {
    _PN = _Ns;
    _Ns = 0;
    _Nr = 0;
    _DHr = header.dh;
    std::tie(_RK, _CKr) = ext.KDF_RK(_RK, ext.DH(_DHs, _DHr));
    _DHs = ext.GENERATE_DH();
    std::tie(_RK, _CKs) = ext.KDF_RK(_RK, ext.DH(_DHs, _DHr));
}

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

    std::stringstream out;
    auto plaintextStream = stream_from_vector(plaintext);
    auto adStream = stream_from_vector(associated_data);
    gcm.encryptWithAd(plaintextStream, adStream, out);

    auto ciphertext = vector_from_stream(out);

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

    std::stringstream out;
    auto ciphertextStream = stream_from_vector(ciphertext);
    auto adStream = stream_from_vector(associated_data);
    gcm.decryptWithAd(ciphertextStream, adStream, out);

    // todo check hmac
    auto plaintext = vector_from_stream(out);
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
