/**
 * @file hmac_base.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief HMAC base class
 * @version 0.1
 * @date 2019-03-30
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_HMAC_BASE_H
#define HELLOWORLD_HMAC_BASE_H

#include <vector>
#include "hmac.h"
#include "mbedtls/md.h"
#include "serializable_error.h"
#include "utils.h"

namespace helloworld {

template <mbedtls_md_type_t Hash = MBEDTLS_MD_SHA512, size_t Size = 64>
class hmac_base : public hmac {
    zero::bytes_t key_;

   public:
    static constexpr mbedtls_md_type_t hmac_type = Hash;
    static constexpr size_t hmac_size = Size;

    hmac_base() = default;

    explicit hmac_base(zero::bytes_t key) : key_(std::move(key)) {}

    hmac_base(const hmac &) = delete;
    hmac_base &operator=(const hmac &) = delete;
    ~hmac_base() override = default;

    /**
     * hmac length getter
     * @return hmac results length
     */
    size_t hmacLength() const override { return hmac_size; }

    /**
     *  @brief set key used to generate hmac
     *
     *  @param newKey key, which will be set as new authentication key
     */
    void setKey(const zero::str_t &newKey) override { key_ = from_hex(newKey); }

    /**
     *  @brief set key used to generate hmac
     *
     *  @param newKey key, which will be set as new authentication key
     */
    void setKey(const zero::bytes_t &newKey) override { key_ = newKey; }

    /**
     * @brief generates HMAC for a message
     *
     * @param message from which, hmac will be generated
     * @return generated HMAC
     */
    std::vector<unsigned char> generate(
        const std::vector<unsigned char> &message) const override {
        std::vector<unsigned char> output{};
        output.resize(hmac_size);

        mbedtls_md_context_t ctx;

        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(hmac_type), 1) !=
            0) {
            throw Error("Failed to start hmac");
        }

        if (mbedtls_md_hmac_starts(&ctx, key_.data(), key_.size()) != 0)
            throw Error("Failed to start hmac");

        if (mbedtls_md_hmac_update(&ctx, message.data(), message.size()) != 0) {
            throw Error("Failed to update HMAC.");
        }

        mbedtls_md_hmac_finish(&ctx, output.data());
        mbedtls_md_free(&ctx);

        return output;
    }

    zero::bytes_t generate(const zero::bytes_t &message) const override {
        zero::bytes_t output{};
        output.resize(hmac_size);

        mbedtls_md_context_t ctx;

        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(hmac_type), 1) !=
            0) {
            throw Error("Failed to start hmac");
        }

        if (mbedtls_md_hmac_starts(&ctx, key_.data(), key_.size()) != 0)
            throw Error("Failed to start hmac");

        if (mbedtls_md_hmac_update(&ctx, message.data(), message.size()) != 0) {
            throw Error("Failed to update HMAC.");
        }

        mbedtls_md_hmac_finish(&ctx, output.data());
        mbedtls_md_free(&ctx);

        return output;
    }
};
}    // namespace helloworld

#endif    // HELLOWORLD_HMAC_BASE_H
