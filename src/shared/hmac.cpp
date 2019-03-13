//
// Created by ivan on 13.3.19.
//

#include <array>
#include "hmac.h"



using namespace helloworld;


HMAC::HMAC(std::vector<unsigned char> key): key_(std::move(key)) {}

std::vector<unsigned char> HMAC::key() const { return key_; }
std::vector<unsigned char>& HMAC::key() { return key_; }

std::string HMAC::generate(std::istream &message) {
    if (!message) throw std::runtime_error("input stream invalid");


    std::array<unsigned char, 4096> buffer;
    std::array<unsigned char, 64> output;

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA512;


    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type) , 1);
    mbedtls_md_hmac_starts(&ctx, key_.data(), key_.size());
    while (message.good()) {
        size_t in_len = read_n(message, buffer.data(), buffer.size());
        if (mbedtls_md_hmac_update(&ctx, buffer.data(), in_len) != 0) {
            throw std::runtime_error("Failed to update HMAC.");
        }
    }

    mbedtls_md_hmac_finish(&ctx, output.data());
    mbedtls_md_free(&ctx);

    return to_hex(output.data(), output.size());
}