//
// Created by horak_000 on 24. 2. 2019.
//

#include "sha_512.h"

namespace helloworld {

    std::string SHA512::get(std::istream &in) {
        while (in.good()) {
            unsigned char input[256];
            size_t in_len = read_n(in, input, 256);
            if (mbedtls_sha512_update_ret(&_context, input, in_len) != 0) {
                throw std::runtime_error("Failed to update hash.");
            }

            unsigned char result[64];
            if (mbedtls_sha512_finish_ret(&_context, result) != 0) {
                throw std::runtime_error("Failed to finish hash.");
            }
            return HexUtils::bin_to_hex(result, 64);
        }
    }
}
