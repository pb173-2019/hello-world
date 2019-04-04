/**
 * @file symmetric_cipher_base.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief request and response structures
 * @version 0.1
 * @date 2019-03-24
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_SYMMETRIC_CIPHER_BASE_H_
#define HELLOWORLD_SHARED_SYMMETRIC_CIPHER_BASE_H_

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

/**
 * Super class for symetric cyphers from mbedetls requiring inicialization vector as well as key
 * @tparam MODE
 * @tparam KEY_SIZE
 * @tparam IV_SIZE
 */
template<mbedtls_cipher_type_t MODE, unsigned KEY_SIZE = 16, unsigned IV_SIZE = 16>
class SymmetricCipherBase : SymmetricCipher {

protected:
    bool dirty = false;

    mbedtls_cipher_context_t _context{};
    std::string _key{};
    std::string _iv{};

    /**
     * @brief Generates random key
     *
     * @return string converted key
     */
    std::string _generateRandomKey() const {
        return to_hex(Random{}.get(key_size));
    }

    /**
     * @brief Generates random initialization vector
     *
     * @return string converted initialization vector
     */
    std::string _generateRandomIv() const {
        return to_hex(Random{}.get(iv_size));
    }

    /**
     * @brief Resets cipher context (necessary if we want to reuse context)
     */
    void _reset() {
        if (mbedtls_cipher_reset(&_context) != 0) {
            throw Error("Failed to re-use the cipher.");
        }
        dirty = false;
    }

    /**
     * @brief Initialization of encryption parameters
     *
     * @param willEncrypt boolean value whether encryption (or decryption) will take place
     */
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

    void _process(const std::vector<unsigned char> &in, std::vector<unsigned char> &out, size_t inputOffset = 0 ) {

        out.resize(in.size() - inputOffset + IV_SIZE);
        size_t out_len;
        if (mbedtls_cipher_update(&_context, in.data() + inputOffset, in.size() - inputOffset, out.data(), &out_len) != 0) {
            throw Error("Failed to update cipher.");
        }


        unsigned char fin[IV_SIZE];
        out.resize(out_len + IV_SIZE);
        size_t fin_len;
        if (mbedtls_cipher_finish(&_context, out.data() + out_len, &fin_len) != 0) {
            throw Error("Failed to finish cipher.");
        }
        out.resize(out_len + fin_len);

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

    ~SymmetricCipherBase() override {
        _key.clear();
        _iv.clear();
        mbedtls_cipher_free(&_context);
    }

    /**
     * @brief Sets block cipher padding
     *
     * @param p padding to use
     */
    void setPadding(Padding p) override {
        mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(p));
    }

    /**
    * @brief Sets encryption key
     *
    * @param newKey
    * @return
    */
    bool setKey(const std::string &newKey) override {
        if (newKey.size() != key_size * 2)
            return false;
        _key = newKey;
        return true;
    }

    /**
     * @brief Sets initialization vector
     *
     * @param newIv new initialization vector
     * @return true if iv set correctly
     */
    bool setIv(const std::string &newIv) override {
        if (newIv.size() != iv_size * 2)
            return false;
        _iv = newIv;
        return true;
    }

    /**
     * @brief Gets encryption key
     *
     * @return encryption key
     */
    const std::string &getKey() const override { return _key; }

    /**
     * @brief Gets initialization vector
     *
     * @return initialization vector
     */
    const std::string &getIv() const override { return _iv; }

    /**
     * @brief Generates random key
     *
     * @return random key string
     */
    std::string generateKey() const override {
        return _generateRandomKey();
    }
};

} // namespace helloworld
#endif //HELLOWORLD_SHARED_SYMMETRIC_CIPHER_BASE_H_
