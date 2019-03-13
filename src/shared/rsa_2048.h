/**
 * @file rsa_2048.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief RSA 2048 wrapper
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_RSA_2048_H_
#define HELLOWORLD_SHARED_RSA_2048_H_

#include <iostream>
#include <stdexcept>
#include <vector>
#include <cmath>

#include "asymmetric_cipher.h"
#include "random.h"

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#define MBEDTLS_PK_PARSE_C


namespace helloworld {

class RSA2048 : public AsymmetricCipher<RSA2048> {

    const static int KEY_SIZE = 2048;
    const static int MAX_DATA_SIZE = 245;

    mbedtls_pk_context key{};

    std::string key_data{};
    bool dirty = false;

public:
    explicit RSA2048() {
        mbedtls_pk_init(&key);
        if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA )) != 0) {
            throw std::runtime_error("Could not initialize RSA ciper.");
        }
        auto* context = (mbedtls_rsa_context *) (key).pk_ctx;
    }

    ~RSA2048() override {
        mbedtls_pk_free(&key);
    }

    void setKey(const std::string &key) override;

    std::vector<unsigned char> encrypt(const std::string &msg) override;

    std::string decrypt(const std::vector<unsigned char> &data) override;

    std::vector<unsigned char> sign(const std::string &hash) override;

    bool verify(const std::vector<unsigned char> &signedData,
                        const std::string &hash) override;

    static std::string generateKey(bool isPublic) {
        Random random{};
        mbedtls_ctr_drbg_context* random_ctx = random.getEngine();

        mbedtls_rsa_context rsa_ctx;
        mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);

        size_t exponent = static_cast<size_t>(std::pow(2, random.getBounded(4, 18)));
        exponent += 1; //primes

        if (mbedtls_rsa_gen_key( &rsa_ctx, mbedtls_ctr_drbg_random, random_ctx, KEY_SIZE, exponent ) != 0) {
            throw std::runtime_error("Could not generate RSA key.");
        }

        mbedtls_rsa_free(&rsa_ctx);

    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_RSA_2048_H_
