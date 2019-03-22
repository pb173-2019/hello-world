/**
 * @file hmac.cpp
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief HMAC class (SHA-512)
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#include <array>

#include "hmac.h"
#include "serializable_error.h"

using namespace helloworld;


void HMAC::setKey(std::vector<unsigned char> newKey) { key_ = std::move(newKey); }

std::array<unsigned char, HMAC::hmac_size> HMAC::generate(const std::vector<unsigned char> &message) const {
    std::array<unsigned char, hmac_size> output{};

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(hmac_type), 1);
    mbedtls_md_hmac_starts(&ctx, key_.data(), key_.size());
    if (mbedtls_md_hmac_update(&ctx, message.data(), message.size()) != 0) {
        throw Error("Failed to update HMAC.");
    }

    mbedtls_md_hmac_finish(&ctx, output.data());
    mbedtls_md_free(&ctx);

    return output;
}