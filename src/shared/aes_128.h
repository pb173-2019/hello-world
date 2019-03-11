//
// Created by horak_000 on 24. 2. 2019.
//
#ifndef HELLOWORLD_SHARED_AES_128_H_
#define HELLOWORLD_SHARED_AES_128_H_

#include <iostream>
#include <stdexcept>
#include <vector>

#include "symmetric_cipher.h"

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace helloworld {

    enum class Padding {
        PKCS7 = MBEDTLS_PADDING_PKCS7,                 /**< PKCS7 padding (default).        */
        ONE_AND_ZEROS = MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
        ZEROS_AND_LEN = MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
        ZEROS = MBEDTLS_PADDING_ZEROS,                 /**< Zero padding (not reversible).  */
        NONE = MBEDTLS_PADDING_NONE,                   /**< Never pad (full blocks only).   */
    };

    class AES128 : public SymmetricCipher {

        std::string key{};
        std::string iv{};
        bool dirty = false;

        mbedtls_cipher_context_t context{};

    public:
        explicit AES128() {
            switch (mbedtls_cipher_setup(
                    &context, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC))) {
                case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
                    throw std::runtime_error("MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA");
                case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
                    throw std::runtime_error("MBEDTLS_ERR_CIPHER_ALLOC_FAILED");
            }
        }

        ~AES128() override {
            mbedtls_cipher_free(&context);
        }

        bool setKey(const std::string &key) override;

        const std::string& getKey() override;

        bool setIv(const std::string &iv) override;

        const std::string& getIv() override;

        void setPadding(Padding p) override;

        void encrypt(std::istream &in, std::ostream& out) override;

        void decrypt(std::istream &in, std::ostream& out) override;

    private:
        void init(bool willEncrypt);
        void process(std::istream& in, std::ostream& out);
        void reset();
    };
}

#endif //HELLOWORLD_SHARED_AES_128_H_
