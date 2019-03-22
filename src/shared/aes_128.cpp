#include "aes_128.h"
#include "utils.h"
#include "random.h"

namespace helloworld {

AES128::AES128() {
    switch (mbedtls_cipher_setup(&_context, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC))) {
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            throw Error("mbedTLS library initialization for aes cipher failed: bad input data.");
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            throw Error("mbedTLS library initialization for aes cipher failed: memory alloc failed.");
        default:
            break;
    }
    setPadding(Padding::PKCS7);
}

bool AES128::setKey(const std::string &key) {
    if (key.size() != KEY_SIZE * 2)
        return false;
    this->_key = key;
    return true;
}

const std::string &AES128::getKey() const {
    return _key;
}

bool AES128::setIv(const std::string &iv) {
    if (iv.size() != IV_SIZE * 2)
        return false;
    this->_iv = iv;
    return true;
}

const std::string &AES128::getIv() const {
    return _iv;
}

void AES128::setPadding(Padding p) {
    mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(p));
}

void AES128::_reset() {
    if (mbedtls_cipher_reset(&_context) != 0) {
        throw Error("Failed to re-use the cipher.");
    }
    dirty = false;
}

void AES128::encrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(true);
    dirty = true;
    _process(in, out);
}

void AES128::decrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        _reset();
    }
    _init(false);
    dirty = true;
    _process(in, out);
}

void AES128::_init(bool willEncrypt) {
    if (_iv.empty()) {
        if (willEncrypt) {
            Random random{};
            std::vector<unsigned char> new_iv = random.get(IV_SIZE);
            _iv = to_hex(new_iv);
        } else {
            throw Error("IV is missing.");
        }
    }

    unsigned char ivData[IV_SIZE];
    from_hex(_iv, ivData, IV_SIZE);
    if (mbedtls_cipher_set_iv(&_context, ivData, IV_SIZE) != 0) {
        throw Error("Failed to initialize init vector - unable to continue.");
    }
    clear<unsigned char>(ivData, IV_SIZE);

    if (_key.empty()) {
        throw Error("Key is missing.");
    }
    unsigned char keyData[KEY_SIZE];
    from_hex(_key, keyData, KEY_SIZE);

    if (mbedtls_cipher_setkey(&_context, keyData, KEY_SIZE * 8, willEncrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
        throw Error("Failed to initialize AES key - unable to continue.");
    }
    clear<unsigned char>(keyData, KEY_SIZE);
}

void AES128::_process(std::istream &in, std::ostream &out) {
    if (!in) throw Error("input stream invalid");
    if (!out) throw Error("output stream invalid");

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n(in, input, 256);
        unsigned char output[256 + IV_SIZE]{}; //256 + block size length
        size_t out_len;

        if (mbedtls_cipher_update(&_context, input, in_len, output, &out_len) != 0) {
            throw Error("Failed to update cipher.");
        }
        write_n(out, output, out_len);
        clear<unsigned char>(output, 256 + IV_SIZE);
    }

    unsigned char fin[IV_SIZE];
    size_t fin_len;
    if (mbedtls_cipher_finish(&_context, fin, &fin_len) != 0) {
        throw Error("Failed to finish cipher.");
    }
    write_n(out, fin, fin_len);
    clear<unsigned char>(fin, fin_len);

    if (!in.good() && !in.eof())
        throw Error("Wrong input file.");
}

} //namespace helloworld