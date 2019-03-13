#include "base_64.h"

#include <stdexcept>

#include "mbedtls/base64.h"

namespace helloworld {

std::vector<unsigned char> Base64::encode(const std::vector<unsigned char>& message) {
    size_t requiredSize;
    mbedtls_base64_encode(nullptr, 0, &requiredSize, message.data(), message.size());

    size_t actualOutput;
    unsigned char encoded[requiredSize];
    if (mbedtls_base64_encode(encoded, requiredSize, &actualOutput, message.data(), message.size()) != 0) {
        throw std::runtime_error("The buffer size provided for Base64 encoder is too small.");
    }
    return std::vector<unsigned char>(encoded, encoded + actualOutput);
}

std::vector<unsigned char> Base64::decode(const std::vector<unsigned char>& data) {
    size_t requiredSize;
    mbedtls_base64_encode(nullptr, 0, &requiredSize, data.data(), data.size());

    size_t actualOutput;
    unsigned char decoded[requiredSize];

    switch (mbedtls_base64_decode(decoded, requiredSize, &actualOutput, data.data(), data.size())) {
        case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
            throw std::runtime_error("The buffer size provided for Base64 encoder is insufficient.");
        case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
            throw std::runtime_error("Invalid Base64 conversion: invalid character.");
        default:
            break;
    }

    return std::vector<unsigned char>(decoded, decoded + actualOutput);
}

} // namespace helloworld
