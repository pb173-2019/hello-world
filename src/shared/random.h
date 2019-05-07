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

#include <mutex>
#include <string>
#include <vector>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace helloworld {

class Random {
    static constexpr size_t RESEED_AFTER = 20;

    // Working with shared resources, so it might be neccessary
    static std::mutex _mutex;

    static mbedtls_entropy_context _entropy;
    static mbedtls_ctr_drbg_context _ctr_drbg;
    static size_t _instance_counter;
    static size_t _use_since_reseed;

   public:
    /**
     * Thread safe wrapper for drbg context, (cannot be member)
     */
    class ContextWrapper {
        std::unique_lock<std::mutex> _lock;
        mbedtls_ctr_drbg_context *_ctr_drbg;

       public:
        ContextWrapper(std::mutex &mutex, mbedtls_ctr_drbg_context *_ctr_drbg);

        /**
         * Returns pointer to underlying context
         * @return pointer to drbg context
         */
        mbedtls_ctr_drbg_context *get();
    };

    explicit Random();

    Random(const Random &other) = delete;

    Random &operator=(const Random &other) = delete;

    /**
     * Generates vector of random data
     *
     * @param size length of vector
     * @return std::vector<unsigned char> vector of unsigned data
     */
    std::vector<unsigned char> get(size_t size);

    /**
     * Generates random number, max 255^3
     * not suitable for short ranges, e.g. 55, 58
     *
     * @param lower lower bound including
     * @param upper upper bound excluding
     * @return size_t number in range <lower, upper)
     */
    size_t getBounded(size_t lower, size_t upper);

    /**
     * Returns ctr_drbg associated context in thread safe wrapper
     *
     * @return mbedtls_ctr_drbg_context* random engine context pointer
     */
    ContextWrapper getEngine();

    ~Random();

   private:
    static void _reseed();
    static void _getSeedEntropy(unsigned char *buff);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_RANDOM_H_
