#include "double_ratchet.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DoubleRatchet::DoubleRatchet(zero::bytes_t SK,
                             zero::bytes_t AD,
                             zero::bytes_t other_dh_public_key)
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

DoubleRatchet::DoubleRatchet(zero::bytes_t SK,
                             zero::bytes_t AD,
                             zero::bytes_t dh_public_key,
                             zero::bytes_t dh_private_key)
    : _state({}), _receivedMessage(true) {
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

DoubleRatchet::DoubleRatchet(DRState state) : _state(std::move(state)) {}

Message DoubleRatchet::RatchetEncrypt(
    const std::vector<unsigned char> &plaintext) {
    zero::bytes_t mk;
    std::tie(_state.CKs, mk) = ext.KDF_CK(_state.CKs, 0x01);
    MessageHeader header = ext.HEADER(_state.DHs, _state.PN, _state.Ns);
    ++_state.Ns;

    return Message(header, ext.ENCRYPT(mk, plaintext, ext.CONCAT(_state.AD, header)));
}

std::vector<unsigned char> DoubleRatchet::RatchetDecrypt(
    const Message &message) {
    DRState oldState = _state;
    try {
        auto result = TryRatchetDecrypt(message);
        _receivedMessage = true;
        return result;
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

    std::vector<unsigned char> plaintext = TrySkippedMessageKeys(header, ciphertext, hmac);
    if (!plaintext.empty()) {
        return plaintext;
    }

    if (header.dh != _state.DHr) {
        SkipMessageKeys(header.pn);
        DHRatchet(header);
    }

    SkipMessageKeys(header.n);
    zero::bytes_t mk;
    std::tie(_state.CKr, mk) = ext.KDF_CK(_state.CKr, 0x01);
    ++_state.Nr;

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_state.AD, header));
}

std::vector<unsigned char> DoubleRatchet::TrySkippedMessageKeys(
        const MessageHeader &header,
        const std::vector<unsigned char> &ciphertext,
        const std::vector<unsigned char> &hmac) {

    auto found = _state.MKSKIPPED.find({header.dh, header.n});
    if (found == _state.MKSKIPPED.end()) {
        return {};
    }

    zero::bytes_t mk = found->second;
    _state.MKSKIPPED.erase(found);

    return ext.DECRYPT(mk, ciphertext, hmac, ext.CONCAT(_state.AD, header));
}

void DoubleRatchet::SkipMessageKeys(size_t until) {
    if (_state.Nr + MAX_SKIP < until) {
        throw Error("skipped more than MAX_SKIP messages in double ratchet");
    }

    if (!_state.CKr.empty()) {
        while (_state.Nr < until) {
            zero::bytes_t mk;
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
