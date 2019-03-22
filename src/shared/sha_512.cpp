#include "sha_512.h"

namespace helloworld {

std::string SHA512::get(std::istream &in)  {
    if (!in) throw Error("input stream invalid");

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n(in, input, 256);
        if (mbedtls_sha512_update_ret(&_context, input, in_len) != 0) {
            throw Error("Failed to update hash.");
        }
    }
    unsigned char result[HASH_SIZE];
    if (mbedtls_sha512_finish_ret(&_context, result) != 0) {
        throw Error("Failed to finish hash.");
    }
    return to_hex(result, HASH_SIZE);
}

} //namespace helloworld
