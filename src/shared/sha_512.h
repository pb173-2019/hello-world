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
    const static int HASH_SIZE = 64;
    mbedtls_sha512_context _context{};

public:
    explicit SHA512() {
        mbedtls_sha512_init(&_context);
        if (mbedtls_sha512_starts_ret(&_context, static_cast<int>(SHA::S512)) != 0) {
            throw std::runtime_error("mbedTLS sha initialization failed");
        }
    }

    ~SHA512() override {
        mbedtls_sha512_free(&_context);
    }

    SHA512(const SHA512 &other) = delete;

    SHA512 &operator=(const SHA512 &other) = delete;

    std::string get(std::istream &in) override;
};

} //namespace helloworld
#endif //HELLOWORLD_SHARED_SHA512_H_
