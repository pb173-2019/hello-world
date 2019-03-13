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
#include <cmath>


#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>

#else
// todo linux
#endif

namespace helloworld {

    class Random {
        mbedtls_entropy_context _entropy{};
        mbedtls_ctr_drbg_context _ctr_drbg{};

    public:
        explicit Random() {
            mbedtls_entropy_init(&_entropy);
            mbedtls_ctr_drbg_init(&_ctr_drbg);
            unsigned char* salt;
            size_t length;

#if defined(WINDOWS)
            HCRYPTPROV hCryptProv;
            BYTE entropy[16];
            if (CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0) != 0) {
                throw std::runtime_error("Could not init windows seed.");
            }
            if (CryptGenRandom(hCryptProv, 8, entropy) == 0) {
                throw std::runtime_error("Could not init windows seed.");
            }
            salt = entropy;
            length = 16;
            for (int i = 0; i < 16; i++) {
                std::cout << entropy << ", ";
            }
            std::cout << "\n";
#else
    //todo linux
            unsigned char data[16];
            salt = data;
            length = 16;
#endif

            if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, salt, length) != 0) {
                throw std::runtime_error("Could not init seed.");
            }
            mbedtls_ctr_drbg_set_prediction_resistance(&_ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);
        }

        Random(const Random &other) = delete;

        Random &operator=(const Random &other) = delete;

        /**
         * Generates vector of random data
         *
         * @param size length of vector
         * @return std::vector<unsigned char> vector of unsigned data
         */
        std::vector<unsigned char> get(size_t size) {
            //todo clear memory, used for key generators
            //todo or better, move data from array to vector
            unsigned char data[size];

            if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, size) != 0) {
                throw std::runtime_error("Could not generate random sequence.");
            }
            std::vector<unsigned char> result(data, data + size);

            //addresses different! copied - insecure
            std::cout << static_cast<const void*>(data) << "\n";
            std::cout << static_cast<const void*>(result.data()) << "\n";
            return result;
        }

        /**
         * Generates random number, max 255^3
         * not suitable for short ranges, e.g. 55, 58
         *
         * @param lower lower bound including
         * @param upper upper bound excluding
         * @return size_t number in range <lower, upper)
         */
        size_t getBounded(size_t lower, size_t upper) {
            unsigned char data[3];
            if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, 3) != 0) {
                throw std::runtime_error("Could not generate random sequence.");
            }

            size_t result = 0;
            for (int i = 0; i < 3; i++) {
                result += static_cast<size_t>(std::pow(255, i)) * data[i];
            }

            result = result % upper;
            if (result >= lower) {
                return result;
            } else {
                return getBounded(lower, upper);
            }
        }

        /**
         * Returns ctr_drbg associated context
         *
         * @return mbedtls_ctr_drbg_context* random engine context pointer
         */
        mbedtls_ctr_drbg_context* getEngine() {
            return &_ctr_drbg;
        }

        ~Random() {
            mbedtls_ctr_drbg_free(&_ctr_drbg);
            mbedtls_entropy_free(&_entropy);
        }
    };
}

#endif //HELLOWORLD_SHARED_RANDOM_H_
