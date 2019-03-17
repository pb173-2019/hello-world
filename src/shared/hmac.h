//
// Created by ivan on 13.3.19.
//

#ifndef HELLOWORLD_HMAC_H
#define HELLOWORLD_HMAC_H
#include <string>
#include <vector>
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"
#include "utils.h"

namespace helloworld {
    class HMAC {
        std::vector<unsigned char> key_;
    public:
        explicit HMAC(std::vector<unsigned char> key);

        HMAC(const HMAC &) = delete;

        HMAC& operator=(const HMAC &) = delete;

        ~HMAC() = default;

        std::vector<unsigned char> key() const;

        std::vector<unsigned char> &key();

        std::string generate(std::istream & /*message*/);
    };
} // helloworld
#endif //HELLOWORLD_HMAC_H
