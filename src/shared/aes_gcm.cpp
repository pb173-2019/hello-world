/**
 * @file request.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief request and response structures
 * @version 0.1
 * @date 2019-03-24
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "config.h"
#include "aes_gcm.h"

#include "symmetric_cipher_base.h"
#include "mbedtls/cipher.h"

using namespace helloworld;

void AESGCM::encrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(true);
    dirty = true;
    std::stringstream tmp;
    _process(in, tmp);

    std::array<unsigned char, 16> tag{};
    if (mbedtls_cipher_write_tag(&_context, tag.data(), 16))
        throw Error("mbedTLS error while generating tag");

    write_n(out, tag.data(), tag.size());
    out << tmp.str();
}

void AESGCM::encryptWithAd(std::istream &in, std::istream &ad, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(true);
    _additional(ad);
    dirty = true;

    std::stringstream tmp;
    _process(in, tmp);
    std::array<unsigned char, 16> tag{};
    if (mbedtls_cipher_write_tag(&_context, tag.data(), 16) != 0)
        throw Error("mbedTLS error while generating tag");

    write_n(out, tag.data(), tag.size());
    out.write(tmp.str().data(), tmp.str().size());
}

void AESGCM::encryptWithAd(const std::vector<unsigned char> &in, const std::vector<unsigned char> &ad, std::vector<unsigned char> &out) {
    if (dirty) {
        _reset();
    }
    _init(true);
    _additional(ad);
    dirty = true;

    _process(in, out);

    std::vector<unsigned char> tag;
    tag.resize(16);
    if (mbedtls_cipher_write_tag(&_context, tag.data(), 16) != 0)
        throw Error("mbedTLS error while generating tag");

    out.insert(out.begin(), tag.begin(), tag.end());
}

void AESGCM::decrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }

    std::array<unsigned char, 16> tag{};
    if (read_n(in, tag.data(), tag.size()) != 16) {
        throw Error("Could not read tag.");
    }
    _init(false);
    dirty = true;
    _process(in, out);

    if (mbedtls_cipher_check_tag(&_context, tag.data(), tag.size()))
        throw Error("mbedTLS authetification error");
}

void AESGCM::decryptWithAd(std::istream &in, std::istream &ad, std::ostream &out) {
    if (dirty) {
        _reset();
    }

    std::array<unsigned char, 16> tag{};
    if (read_n(in, tag.data(), tag.size()) != 16) {
        throw Error("Could not read tag.");
    }

    _init(false);
    _additional(ad);
    dirty = true;
    _process(in, out);

    if (mbedtls_cipher_check_tag(&_context, tag.data(), tag.size()))
        throw Error("mbedTLS authetification error");
}

void AESGCM::decryptWithAd(const std::vector<unsigned char> &in, const std::vector<unsigned char> &ad, std::vector<unsigned char> &out) {
    if (dirty) {
        _reset();
    }

    std::vector<unsigned char> tag;
    std::copy(in.begin(), in.begin() + TAG_LEN, std::back_inserter(tag));

    _init(false);
    _additional(ad);
    dirty = true;
    _process(in, out, TAG_LEN);

    if (mbedtls_cipher_check_tag(&_context, tag.data(), tag.size()))
        throw Error("mbedTLS authetification error");
}

void AESGCM::_additional(std::istream &ad) {
    if (!ad) throw Error("input stream invalid");

    while (ad.good()) {
        unsigned char input[256];

        size_t in_len = read_n(ad, input, 256);

        if (mbedtls_cipher_update_ad(&_context, input, in_len) != 0) {
            throw Error("Failed to update ad.");
        }
    }
}

void AESGCM::_additional(const std::vector<unsigned char>& ad) {
    if (mbedtls_cipher_update_ad(&_context, ad.data(), ad.size()) != 0) {
        throw Error("Failed to update ad.");
    }
}