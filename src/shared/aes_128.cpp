//
// Created by horak_000 on 24. 2. 2019.
//

#include "aes_128.h"
#include "utils.h"
#include "random.h"

namespace helloworld {

    void AES128::setKey(const std::string &key) {
        if (key.size() != 32)
            throw std::runtime_error("Invalid key length.");
        this->key = key;
    }

    const std::string& AES128::getKey() {
        return key;
    }

    void AES128::setIv(const std::string &iv) {
        if (iv.size() != 32)
            throw std::runtime_error("Invalid init vector length.");
        this->iv = iv;
    }

    const std::string& AES128::getIv() {
        return iv;
    }

    void AES128::setPadding(Padding p) {
        mbedtls_cipher_set_padding_mode(&context, static_cast<mbedtls_cipher_padding_t>(p));
    }

    void AES128::encrypt(std::istream &in, std::ostream& out) {
        init(true);
        process(in, out);
    }

    void AES128::decrypt(std::istream &in, std::ostream& out) {
        init(false);
        process(in, out);
    }

    void AES128::init(bool willEncrypt) {
        if (iv.empty()) {
            if (willEncrypt) {
                Random random{};
                std::vector<unsigned char> new_iv = random.get<16>();
                iv = HexUtils::bin_to_hex(new_iv.data(), new_iv.size());
            } else {
                throw std::runtime_error("IV is missing.");
            }
        } else {
            unsigned char ivData[16];
            HexUtils::hex_to_bin(key, ivData);
            if (mbedtls_cipher_set_iv(&context, ivData, 16) != 0) {
                throw std::runtime_error("Failed to initialize init vector - unable to continue.");
            }
        }

        if (key.empty()) {
            throw std::runtime_error("Key is missing.");
        } else {
            unsigned char keyData[16];
            HexUtils::hex_to_bin(key, keyData);

            if (mbedtls_cipher_setkey(&context, keyData, 128, willEncrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
                throw std::runtime_error("Failed to initialize AES key - unable to continue.");
            }
        }
    }

    void AES128::process(std::istream& in, std::ostream& out) {
        while (in.good()) {
            unsigned char input[256];
            size_t in_len = read_n(in, input, 256);
            unsigned char output[272]{}; //256 + block size length
            size_t out_len;

            if (mbedtls_cipher_update(&context, input, in_len, output, &out_len) != 0) {
                throw std::runtime_error("Failed to update cipher.");
            }
            write_n(out, output, out_len);
        }

        unsigned char fin[16];
        size_t fin_len;
        if (mbedtls_cipher_finish(&context, fin, &fin_len) != 0) {
            throw std::runtime_error("Failed to finish cipher.");
        }
        write_n(out, fin, fin_len);
    }
}