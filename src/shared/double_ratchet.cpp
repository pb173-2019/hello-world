#include "double_ratchet.h"
#include <stdexcept>
#include <utility>

namespace helloworld {

DoubleRatchet::DoubleRatchet(int SK, int bob_dh_public_key) {
    _DHs = ext.GENERATE_DH();
    _DHr = bob_dh_public_key;
    std::tie(_RK, _CKs) = ext.KDF_RK(SK, ext.DH(_DHs, _DHr));
    _CKr = {};
    _Ns = 0;
    _Nr = 0;
    _PN = 0;
    _MKSKIPPED = {};
}

DoubleRatchet::DoubleRatchet(int SK, size_t bob_dh_key_pair) {
    _DHs = bob_dh_key_pair;
    _DHr = {};
    _RK = SK;
    _CKs = {};
    _CKr = {};
    _Ns = 0;
    _Nr = 0;
    _PN = 0;
    _MKSKIPPED = {};
}

Message DoubleRatchet::RatchetEncrypt(int plaintext, int AD) {
    int mk;
    std::tie(_CKs, mk) = ext.KDF_CK(_CKs);
    Header header = ext.HEADER(_DHs, _PN, _Ns);
    ++_Ns;

    return {header, ext.ENCRYPT(mk, plaintext, ext.CONCAT(AD, header))};
}

int DoubleRatchet::RatchetDecrypt(const Header &header, int ciphertext,
                                  int AD) {
    auto plaintext = TrySkippedMessageKeys(header, ciphertext, AD);
    if (plaintext) {
        return plaintext;
    }

    if (header.dh != _DHr) {
        SkipMessageKeys(header.pn);
        DHRatchet(header);
    }

    SkipMessageKeys(header.n);
    int mk;
    std::tie(_CKr, mk) = ext.KDF_CK(_CKr);
    ++_Nr;

    return ext.DECRYPT(mk, ciphertext, ext.CONCAT(AD, header));
}

int DoubleRatchet::TrySkippedMessageKeys(const Header &header, int ciphertext,
                                         int AD) {
    auto found = _MKSKIPPED.find({header.dh, header.n});
    if (found == _MKSKIPPED.end()) {
        return 0; /* None */
    }

    int mk = found->second;
    _MKSKIPPED.erase(found);

    return ext.DECRYPT(mk, ciphertext, ext.CONCAT(AD, header));
}

int DoubleRatchet::SkipMessageKeys(int until) {
    if (_Nr + MAX_SKIP < until) {
        throw std::runtime_error(
            "skipped more than MAX_SKIP messages in double ratchet");
    }

    if (_CKr) {
        while (_Nr < until) {
            int mk;
            std::tie(_CKr, mk) = ext.KDF_CK(_CKr);
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

}    // namespace helloworld