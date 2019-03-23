//
// Created by ivan on 23.3.19.
//

#ifndef HELLOWORLD_SYMMETRIC_CIPHER_BASE_H
#define HELLOWORLD_SYMMETRIC_CIPHER_BASE_H

#include "random.h"
#include "mbedtls/cipher.h"
#include "serializable_error.h"
#include "symmetric_cipher.h"
#include "utils.h"

namespace helloworld {

    enum class Padding {
        PKCS7 = MBEDTLS_PADDING_PKCS7,                 /**< PKCS7 padding (default).        */
        ONE_AND_ZEROS = MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
        ZEROS_AND_LEN = MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
        ZEROS = MBEDTLS_PADDING_ZEROS,                 /**< Zero padding (not reversible).  */
        NONE = MBEDTLS_PADDING_NONE,                   /**< Never pad (full blocks only).   */
    };

    template<mbedtls_cipher_type_t MODE, unsigned KEY_SIZE = 16, unsigned IV_SIZE = 16>
    class SymmetricCipherBase : SymmetricCipher {

    protected:
        bool dirty = false;

        mbedtls_cipher_context_t _context{};
        std::string _key{};
        std::string _iv{};

        std::string _generateRandomKey() const {
            return to_hex(Random{}.get(key_size));
        }

        std::string _generateRandomIv() const {
            return to_hex(Random{}.get(iv_size));
        }

        void _reset() {
            if (mbedtls_cipher_reset(&_context) != 0) {
                throw Error("Failed to re-use the cipher.");
            }
            dirty = false;
        }

        void _init(bool willEncrypt) {
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

            if (mbedtls_cipher_setkey(&_context, keyData, KEY_SIZE * 8,
                                      willEncrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
                throw Error("Failed to initialize AES key - unable to continue.");
            }
            clear<unsigned char>(keyData, KEY_SIZE);
        }

        void _process(std::istream &in, std::ostream &out) {
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

    public:
        static constexpr unsigned key_size = KEY_SIZE;
        static constexpr unsigned iv_size = IV_SIZE;

        SymmetricCipherBase() {
            switch (mbedtls_cipher_setup(&_context, mbedtls_cipher_info_from_type(MODE))) {
                case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
                    throw Error("mbedTLS library initialization for aes cipher failed: bad input data.");
                case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
                    throw Error("mbedTLS library initialization for aes cipher failed: memory alloc failed.");
                default:
                    break;
            }
            setPadding(Padding::PKCS7);
        }

        ~SymmetricCipherBase() {
            _key.clear();
            _iv.clear();
            mbedtls_cipher_free(&_context);
        }

        void setPadding(Padding p) override {
            mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(p));
        }

        bool setKey(const std::string &newKey) override {
            if (newKey.size() != key_size * 2)
                return false;
            _key = newKey;
            return true;
        }

        bool setIv(const std::string &newIv) override {
            if (newIv.size() != iv_size * 2)
                return false;
            _iv = newIv;
            return true;
        }

        const std::string &getKey() const override { return _key; }

        const std::string &getIv() const override { return _iv; }

        std::string generateKey() const override {
            return _generateRandomKey();
        }
    };

} // namespace helloworld
#endif //HELLOWORLD_SYMMETRIC_CIPHER_BASE_H
