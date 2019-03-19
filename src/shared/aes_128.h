/**
 * @file aes_128.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief AES128 wrapper
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_AES_128_H_
#define HELLOWORLD_SHARED_AES_128_H_

#include <iostream>
#include <stdexcept>
#include <vector>

#include "symmetric_cipher.h"
#include "random.h"
#include "utils.h"

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace helloworld {

//for testing purposes
enum class Padding {
    PKCS7 = MBEDTLS_PADDING_PKCS7,                 /**< PKCS7 padding (default).        */
    ONE_AND_ZEROS = MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    ZEROS_AND_LEN = MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    ZEROS = MBEDTLS_PADDING_ZEROS,                 /**< Zero padding (not reversible).  */
    NONE = MBEDTLS_PADDING_NONE,                   /**< Never pad (full blocks only).   */
};

class AES128 : public SymmetricCipher {

    std::string _key{};
    std::string _iv{};
    bool dirty = false;

    mbedtls_cipher_context_t _context{};

public:
    const static int KEY_SIZE = 16;
    const static int IV_SIZE = 16;

    explicit AES128();

    AES128(const AES128& other) = delete;

    AES128&operator=(const AES128& other) = delete;

    ~AES128() override {
        _key.clear();
        _iv.clear();
        mbedtls_cipher_free(&_context);
    }

    bool setKey(const std::string &key) override;

    const std::string &getKey() const override;

    bool setIv(const std::string &iv) override;

    const std::string &getIv() const override;

    void setPadding(Padding p) override;

    void encrypt(std::istream &in, std::ostream &out) override;

    void decrypt(std::istream &in, std::ostream &out) override;

    std::string generateKey() const override {
        std::vector<unsigned char> data = Random{}.get(16);
        std::string hex = to_hex(data);
        clear<unsigned char>(data.data(), data.size());
        return hex;
    }

private:
    void _init(bool willEncrypt);

    void _process(std::istream &in, std::ostream &out);

    void _reset();
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_AES_128_H_
