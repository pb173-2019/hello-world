//
// Created by horak_000 on 24. 2. 2019.
//
#ifndef HELLOWORLD_SHARED_SHA512_H_
#define HELLOWORLD_SHARED_SHA512_H_

#include <stdexcept>

#include "hash.h"
#include "utils.h"

#include "mbedtls/sha512.h"

namespace helloworld {

    enum class SHA {
        S512 = 0,
        S384 = 1
    };

    class SHA512 : Hash {
        mbedtls_sha512_context _context{};

    public:
        explicit SHA512() {
            mbedtls_sha512_init(&_context);
            mbedtls_sha512_starts_ret(&_context, static_cast<int>(SHA::S512));
        }

        ~SHA512() override {
            mbedtls_sha512_free(&_context);
        }

        SHA512(const SHA512 &other) = delete;

        SHA512 &operator=(const SHA512 &other) = delete;

        std::string get(std::istream &in) override;
    };

}
#endif //HELLOWORLD_SHARED_SHA512_H_
