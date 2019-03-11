//
// Created by horak_000 on 24. 2. 2019.
//

#include "aes_128.h"
#include "utils.h"
#include "random.h"

namespace helloworld {

    bool AES128::setKey(const std::string &key) {
        if (key.size() != 32)
            return false;
        this->key = key;
        return true;
    }

    const std::string& AES128::getKey() {
        return key;
    }

    bool AES128::setIv(const std::string &iv) {
        if (iv.size() != 32)
            return false;
        this->iv = iv;
        return true;
    }

    const std::string& AES128::getIv() {
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

    void AES128::encrypt(std::istream &in, std::ostream& out) {
        if (dirty) {
            reset();
        }
        init(true);
        dirty = true;
        process(in, out);
    }

    void AES128::decrypt(std::istream &in, std::ostream& out) {
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
                std::vector<unsigned char> new_iv = random.get<16>();
                iv = to_hex(new_iv);
            } else {
                throw std::runtime_error("IV is missing.");
            }
        } else {
            unsigned char ivData[16];
            from_hex(key, ivData, 16);
            if (mbedtls_cipher_set_iv(&context, ivData, 16) != 0) {
                throw std::runtime_error("Failed to initialize init vector - unable to continue.");
            }
        }

        if (key.empty()) {
            throw std::runtime_error("Key is missing.");
        } else {
            unsigned char keyData[16];
            from_hex(key, keyData, 16);

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