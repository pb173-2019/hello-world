/**
 * @file random.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief DRBG random wrapper
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef HELLOWORLD_SHARED_RANDOM_H_
#define HELLOWORLD_SHARED_RANDOM_H_

#include <iostream>
#include <stdexcept>
#include <vector>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace helloworld {

    class Random {
        mbedtls_entropy_context _entropy{};
        mbedtls_ctr_drbg_context _ctr_drbg{};

    public:
        Random() : Random("some_random_sequence") {}

        explicit Random(const std::string &salt) {
            mbedtls_entropy_init(&_entropy);
            mbedtls_ctr_drbg_init(&_ctr_drbg);

            auto *temp = (const unsigned char *) salt.c_str();
            if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, temp, salt.length()) != 0) {
                throw std::runtime_error("Could not init seed.");
            }
            mbedtls_ctr_drbg_set_prediction_resistance(&_ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);
        }

        Random(const Random &other) = delete;

        Random &operator=(const Random &other) = delete;

        template<size_t N>
        std::vector<unsigned char> get() {
            unsigned char data[N];
            if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, N) != 0) {
                throw std::runtime_error("Could not generate random sequence.");
            }
            return std::vector<unsigned char>(data, data + N);
        }

        ~Random() {
            mbedtls_ctr_drbg_free(&_ctr_drbg);
            mbedtls_entropy_free(&_entropy);
        }
    };
}

#endif //HELLOWORLD_SHARED_RANDOM_H_
