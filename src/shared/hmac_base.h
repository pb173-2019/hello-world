//
// Created by ivan on 31.3.19.
//

#ifndef HELLOWORLD_HMAC_BASE_H
#define HELLOWORLD_HMAC_BASE_H

#include <vector>
#include "mbedtls/md.h"
#include "serializable_error.h"
#include "utils.h"
#include "hmac.h"

namespace helloworld {

    template<mbedtls_md_type_t Hash = MBEDTLS_MD_SHA512, size_t Size = 64>
    class hmac_base : public hmac {
        std::vector<unsigned char> key_;
    public:
        static constexpr mbedtls_md_type_t hmac_type = Hash;
        static constexpr size_t hmac_size = Size;

        hmac_base() = default;

        // Copying is not available
        hmac_base(const hmac &) = delete;

        hmac_base &operator=(const hmac &) = delete;

        ~hmac_base() override {
            key_.clear();
        };

        /**
         * hmac length getter
         * @return hmac results length
         */
        size_t hmacLength() const override {
            return hmac_size;
        }

        /**
         *  @brief set key used to generate hmac
         *
         *  @param newKey key, which will be set as new authentication key
         */
        void setKey(const std::string &newKey) override {
            key_ = from_hex(newKey);
        }

        /**
         * @brief generates HMAC for a message
         *
         * @param message from which, hmac will be generated
         * @return generated HMAC
         */
        std::vector<unsigned char> generate(const std::vector<unsigned char> &message) const override {
            std::vector<unsigned char> output{};
            output.resize(hmac_size);

            mbedtls_md_context_t ctx;

            mbedtls_md_init(&ctx);
            if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(hmac_type), 1) != 0) {
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
} // namespace helloworld


#endif //HELLOWORLD_HMAC_BASE_H
