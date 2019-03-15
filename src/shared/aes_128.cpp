#include "aes_128.h"
#include "utils.h"
#include "random.h"

namespace helloworld {

AES128::AES128() {
    switch (mbedtls_cipher_setup(&context, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC))) {
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            throw std::runtime_error("mbedTLS library initialization for aes cipher failed: bad input data.");
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            throw std::runtime_error("mbedTLS library initialization for aes cipher failed: memory alloc failed.");
    }
    setPadding(Padding::PKCS7);
}

bool AES128::setKey(const std::string &key) {
    if (key.size() != KEY_SIZE * 2)
        return false;
    this->key = key;
    return true;
}

const std::string &AES128::getKey() {
    return key;
}

bool AES128::setIv(const std::string &iv) {
    if (iv.size() != IV_SIZE * 2)
        return false;
    this->iv = iv;
    return true;
}

const std::string &AES128::getIv() {
    return iv;
}

void AES128::setPadding(Padding p) {
    mbedtls_cipher_set_padding_mode(&context, static_cast<mbedtls_cipher_padding_t>(p));
}

void AES128::reset() {
    if (mbedtls_cipher_reset(&context) != 0) {
        throw std::runtime_error("Failed to re-use the cipher.");
    }
    dirty = false;
}

void AES128::encrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        reset();
    }
    init(true);
    dirty = true;
    process(in, out);
}

void AES128::decrypt(std::istream &in, std::ostream &out) {
    if (dirty) {
        reset();
    }
    init(false);
    dirty = true;
    process(in, out);
}

void AES128::init(bool willEncrypt) {
    if (iv.empty()) {
        if (willEncrypt) {
            Random random{};
            std::vector<unsigned char> new_iv = random.get(IV_SIZE);
            iv = to_hex(new_iv);
        } else {
            throw std::runtime_error("IV is missing.");
        }
    }

    unsigned char ivData[IV_SIZE];
    from_hex(iv, ivData, IV_SIZE);
    if (mbedtls_cipher_set_iv(&context, ivData, IV_SIZE) != 0) {
        throw std::runtime_error("Failed to initialize init vector - unable to continue.");
    }
    clear<unsigned char>(ivData, IV_SIZE);

    if (key.empty()) {
        throw std::runtime_error("Key is missing.");
    }
    unsigned char keyData[KEY_SIZE];
    from_hex(key, keyData, KEY_SIZE);

    if (mbedtls_cipher_setkey(&context, keyData, KEY_SIZE * 8, willEncrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
        throw std::runtime_error("Failed to initialize AES key - unable to continue.");
    }
    clear<unsigned char>(keyData, KEY_SIZE);
}

void AES128::process(std::istream &in, std::ostream &out) {
    if (!in) throw std::runtime_error("input stream invalid");
    if (!out) throw std::runtime_error("output stream invalid");

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n(in, input, 256);
        unsigned char output[256 + IV_SIZE]{}; //256 + block size length
        size_t out_len;

        if (mbedtls_cipher_update(&context, input, in_len, output, &out_len) != 0) {
            throw std::runtime_error("Failed to update cipher.");
        }
        write_n(out, output, out_len);
        clear<unsigned char>(output, 256 + IV_SIZE);
    }

    unsigned char fin[IV_SIZE];
    size_t fin_len;
    if (mbedtls_cipher_finish(&context, fin, &fin_len) != 0) {
        throw std::runtime_error("Failed to finish cipher.");
    }
    write_n(out, fin, fin_len);
    clear<unsigned char>(fin, fin_len);

    if (!in.good() && !in.eof())
        throw std::runtime_error("Wrong input file.");
}

} //namespace helloworld