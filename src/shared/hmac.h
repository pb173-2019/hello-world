/**
 * @file hmac.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief HMAC class (SHA-512)
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_HMAC_H
#define HELLOWORLD_HMAC_H

#include <string>
#include <vector>
#include <array>
#include "mbedtls/md.h"
#include "mbedtls/sha512.h"
#include "utils.h"

namespace helloworld {

class HMAC {
    std::vector<unsigned char> key_;
public:
    static constexpr mbedtls_md_type_t hmac_type = MBEDTLS_MD_SHA512;
    static constexpr size_t hmac_size = 64;

    explicit HMAC() = default;

    // Copying is not available
    HMAC(const HMAC &) = delete;

    HMAC &operator=(const HMAC &) = delete;

    ~HMAC() = default;

    /**
     *  @brief set key used to generate hmac
     *
     *  @param newKey key, which will be set as new authentication key
     */
    void setKey(std::vector<unsigned char> newKey);

    /**
     * @brief generates HMAC for a message
     *
     * @param message input stream from which, hmac will be generated
     * @return std::string generated HMAC
     */
    std::array<unsigned char, hmac_size> generate(const std::vector<unsigned char> &message) const;
};

} // helloworld

#endif //HELLOWORLD_HMAC_H
