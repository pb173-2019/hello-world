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

    std::array<unsigned char, 16> tag;
    if (mbedtls_cipher_write_tag(&_context, tag.data(), 16))
        throw Error("mbedTLS error while generating tag");

    out.write(reinterpret_cast<char *>(tag.data()), tag.size());
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
    std::array<unsigned char, 16> tag;
    if (mbedtls_cipher_write_tag(&_context, tag.data(), 16) != 0)
        throw Error("mbedTLS error while generating tag");

    write_n(out, tag.data(), tag.size());
    out.write(tmp.str().data(), tmp.str().size());
}


void AESGCM::decrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }

    std::array<unsigned char, 16> tag;
    in.read(reinterpret_cast<char *>(tag.data()), tag.size());

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


    std::array<unsigned char, 16> tag;
    in.read(reinterpret_cast<char *>(tag.data()), tag.size());

    _init(false);
    _additional(ad);
    dirty = true;
    _process(in, out);

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