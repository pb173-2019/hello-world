#include "sha_512.h"

namespace helloworld {

std::string SHA512::getHex(std::istream &in) {
    std::vector<unsigned char> data = get(in);
    std::string hex = to_hex(data);
    return hex;
}

std::string SHA512::getHex(const std::string &in) {
    std::vector<unsigned char> data = get(in);
    std::string hex = to_hex(data);
    return hex;
}

std::string SHA512::getHex(const zero::str_t &in) {
    zero::bytes_t data = getSafe(in);
    zero::str_t hex = to_hex(data);
    return std::string(hex.data(), hex.size());
}

zero::str_t SHA512::getSafeHex(const zero::str_t& in) {
    zero::bytes_t data = getSafe(in);
    zero::str_t hex = to_hex(data);
    return hex;
}

std::vector<unsigned char> SHA512::get(std::istream &in) {
    if (!in) throw Error("input stream invalid");

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n(in, input, 256);
        if (mbedtls_sha512_update_ret(&_context, input, in_len) != 0) {
            throw Error("Failed to update hash.");
        }
    }
    std::vector<unsigned char> result(HASH_SIZE);
    if (mbedtls_sha512_finish_ret(&_context, result.data()) != 0) {
        throw Error("Failed to finish hash.");
    }
    return result;
}

std::vector<unsigned char> SHA512::get(const std::string &in) {
    if (mbedtls_sha512_update_ret(&_context, reinterpret_cast<const unsigned char *>(in.data()), in.size()) != 0) {
        throw Error("Failed to update hash.");
    }
    std::vector<unsigned char> result(HASH_SIZE);
    if (mbedtls_sha512_finish_ret(&_context, result.data()) != 0) {
        throw Error("Failed to finish hash.");
    }
    return result;
}

zero::bytes_t SHA512::getSafe(const std::string& in) {
    if (mbedtls_sha512_update_ret(&_context, reinterpret_cast<const unsigned char *>(in.data()), in.size()) != 0) {
        throw Error("Failed to update hash.");
    }
    zero::bytes_t result(HASH_SIZE);
    if (mbedtls_sha512_finish_ret(&_context, result.data()) != 0) {
        throw Error("Failed to finish hash.");
    }
    return result;
}

zero::bytes_t SHA512::getSafe(const zero::str_t &in) {
    if (mbedtls_sha512_update_ret(&_context, reinterpret_cast<const unsigned char *>(in.data()), in.size()) != 0) {
        throw Error("Failed to update hash.");
    }
    zero::bytes_t result(HASH_SIZE);
    if (mbedtls_sha512_finish_ret(&_context, result.data()) != 0) {
        throw Error("Failed to finish hash.");
    }
    return result;
}


} //namespace helloworld
