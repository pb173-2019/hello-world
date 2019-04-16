#include "double_ratchet.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DoubleRatchet::DoubleRatchet(std::vector<unsigned char> SK,
                             std::vector<unsigned char> AD,
                             std::vector<unsigned char> other_dh_public_key)
    : _state({}) {
    _state.DHs = ext.GENERATE_DH();
    _state.DHr = std::move(other_dh_public_key);
    _state.CKr = {};
    _state.Ns = 0;
    _state.Nr = 0;
    _state.PN = 0;
    _state.MKSKIPPED = {};
    _state.AD = std::move(AD);
    std::tie(_state.RK, _state.CKs) =
        ext.KDF_RK(std::move(SK), ext.DH(_state.DHs, _state.DHr));
}

DoubleRatchet::DoubleRatchet(std::vector<unsigned char> SK,
                             std::vector<unsigned char> AD,
                             std::vector<unsigned char> dh_public_key,
                             std::vector<unsigned char> dh_private_key)
    : _state({}) {
    _state.DHs = {std::move(dh_public_key), std::move(dh_private_key)};
    _state.DHr = {};
    _state.RK = std::move(SK);
    _state.CKs = {};
    _state.CKr = {};
    _state.Ns = 0;
    _state.Nr = 0;
    _state.PN = 0;
    _state.MKSKIPPED = {};
    _state.AD = std::move(AD);
}

Message DoubleRatchet::RatchetEncrypt(
    const std::vector<unsigned char> &plaintext) {
    key mk;
    std::tie(_state.CKs, mk) = ext.KDF_CK(_state.CKs, 0x01);
    MessageHeader header = ext.HEADER(_state.DHs, _state.PN, _state.Ns);
    ++_state.Ns;

    return Message(header,
                   ext.ENCRYPT(mk, plaintext, ext.CONCAT(_state.AD, header)));
}

std::vector<unsigned char> DoubleRatchet::RatchetDecrypt(
    const Message &message) {
    DRState oldState = _state;
    try {
        return TryRatchetDecrypt(message);
    } catch (Error &e) {
        _state = oldState;
        return {};
    }
}

std::vector<unsigned char> DoubleRatchet::TryRatchetDecrypt(
    const Message &message) {
    auto header = message.header;
    auto ciphertext = message.ciphertext;
    auto hmac = message.hmac;

    key plaintext = TrySkippedMessageKeys(header, ciphertext, hmac);
    if (!plaintext.empty()) {
        return plaintext;
    }

    if (header.dh != _state.DHr) {
        SkipMessageKeys(header.pn);
        DHRatchet(header);
    }

    SkipMessageKeys(header.n);
    key mk;
    std::tie(_state.CKr, mk) = ext.KDF_CK(_state.CKr, 0x01);
    ++_state.Nr;

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_state.AD, header));
}

key DoubleRatchet::TrySkippedMessageKeys(const MessageHeader &header,
                                         const key &ciphertext,
                                         const key &hmac) {
    auto found = _state.MKSKIPPED.find({header.dh, header.n});
    if (found == _state.MKSKIPPED.end()) {
        return {};
    }

    key mk = found->second;
    _state.MKSKIPPED.erase(found);

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_state.AD, header));
}

void DoubleRatchet::SkipMessageKeys(size_t until) {
    if (_state.Nr + MAX_SKIP < until) {
        throw Error("skipped more than MAX_SKIP messages in double ratchet");
    }

    if (!_state.CKr.empty()) {
        while (_state.Nr < until) {
            key mk;
            std::tie(_state.CKr, mk) = ext.KDF_CK(_state.CKr, 0x01);
            _state.MKSKIPPED.emplace(std::make_pair(_state.DHr, _state.Nr), mk);
            ++_state.Nr;
        }
    }
}

void DoubleRatchet::DHRatchet(const MessageHeader &header) {
    _state.PN = _state.Ns;
    _state.Ns = 0;
    _state.Nr = 0;
    _state.DHr = header.dh;
    std::tie(_state.RK, _state.CKr) =
        ext.KDF_RK(_state.RK, ext.DH(_state.DHs, _state.DHr));
    _state.DHs = ext.GENERATE_DH();
    std::tie(_state.RK, _state.CKs) =
        ext.KDF_RK(_state.RK, ext.DH(_state.DHs, _state.DHr));
}

}    // namespace helloworld
