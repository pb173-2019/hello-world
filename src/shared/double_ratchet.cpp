#include "double_ratchet.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DoubleRatchet::DoubleRatchet(std::vector<unsigned char> SK,
                             std::vector<unsigned char> AD,
                             std::vector<unsigned char> other_dh_public_key)
    : _DHs(ext.GENERATE_DH()),
      _DHr(std::move(other_dh_public_key)),
      _CKr({}),
      _Ns(0),
      _Nr(0),
      _PN(0),
      _MKSKIPPED({}),
      _AD(std::move(AD)) {
    std::tie(_RK, _CKs) = ext.KDF_RK(std::move(SK), ext.DH(_DHs, _DHr));
}

DoubleRatchet::DoubleRatchet(std::vector<unsigned char> SK,
                             std::vector<unsigned char> AD,
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
      _MKSKIPPED({}),
      _AD(std::move(AD)) {}

Message DoubleRatchet::RatchetEncrypt(
    const std::vector<unsigned char> &plaintext) {
    key mk;
    std::tie(_CKs, mk) = ext.KDF_CK(_CKs, 0x01);
    MessageHeader header = ext.HEADER(_DHs, _PN, _Ns);
    ++_Ns;

    return Message(header, ext.ENCRYPT(mk, plaintext, ext.CONCAT(_AD, header)));
}

std::vector<unsigned char> DoubleRatchet::RatchetDecrypt(
    const Message &message) {
    auto header = message.header;
    auto ciphertext = message.ciphertext;
    auto hmac = message.hmac;

    key plaintext = TrySkippedMessageKeys(header, ciphertext, hmac);
    if (!plaintext.empty()) {
        return plaintext;
    }

    if (header.dh != _DHr) {
        SkipMessageKeys(header.pn);
        DHRatchet(header);
    }

    SkipMessageKeys(header.n);
    key mk;
    std::tie(_CKr, mk) = ext.KDF_CK(_CKr, 0x01);
    ++_Nr;

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_AD, header));
}

key DoubleRatchet::TrySkippedMessageKeys(const MessageHeader &header,
                                         const key &ciphertext,
                                         const key &hmac) {
    auto found = _MKSKIPPED.find({header.dh, header.n});
    if (found == _MKSKIPPED.end()) {
        return {};
    }

    key mk = found->second;
    _MKSKIPPED.erase(found);

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_AD, header));
}

void DoubleRatchet::SkipMessageKeys(size_t until) {
    if (_Nr + MAX_SKIP < until) {
        throw Error("skipped more than MAX_SKIP messages in double ratchet");
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

void DoubleRatchet::DHRatchet(const MessageHeader &header) {
    _PN = _Ns;
    _Ns = 0;
    _Nr = 0;
    _DHr = header.dh;
    std::tie(_RK, _CKr) = ext.KDF_RK(_RK, ext.DH(_DHs, _DHr));
    _DHs = ext.GENERATE_DH();
    std::tie(_RK, _CKs) = ext.KDF_RK(_RK, ext.DH(_DHs, _DHr));
}

}    // namespace helloworld
