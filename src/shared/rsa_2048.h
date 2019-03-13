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
#include "mbedtls/bignum.h"

#define MBEDTLS_PK_PARSE_C


namespace helloworld {

class RSA2048 : public AsymmetricCipher {

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

    std::string generateKeyPair() override {
        Random random{};
        mbedtls_ctr_drbg_context* random_ctx = random.getEngine();

        if (!valid()) throw std::runtime_error("Could not generate RSA key.");
        auto* rsa_ctx = (mbedtls_rsa_context *) (key).pk_ctx;

        int exponent = static_cast<int>(std::pow(2, random.getBounded(4, 18)));
        exponent += 1; //primes

        std::cout << exponent << "\n";

        if (mbedtls_rsa_gen_key( rsa_ctx, mbedtls_ctr_drbg_random, random_ctx, KEY_SIZE, exponent ) != 0) {
            throw std::runtime_error("Could not generate RSA key.");
        }

        unsigned char buffer[MBEDTLS_MPI_MAX_SIZE];
        int olen;

        if ((olen = mbedtls_pk_write_pubkey_der( &key, buffer, MBEDTLS_MPI_MAX_SIZE)) < 0) {
            throw std::runtime_error("Could not write public key.");
        }

        for (int i = MBEDTLS_MPI_MAX_SIZE - olen; i < MBEDTLS_MPI_MAX_SIZE; i++) {
            std::cout << buffer[i];
        }
        std::cout << "\n\n";


        if ((olen = mbedtls_pk_write_key_der( &key, buffer, MBEDTLS_MPI_MAX_SIZE)) < 0) {
            throw std::runtime_error("Could not write public key.");
        }

        for (int i = MBEDTLS_MPI_MAX_SIZE - olen; i < MBEDTLS_MPI_MAX_SIZE; i++) {
            std::cout << buffer[i];
        }
        std::cout << "\n\n";
    }

private:
    bool valid() {
        return mbedtls_pk_can_do( &key, MBEDTLS_PK_RSA ) == 1;
    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_RSA_2048_H_
