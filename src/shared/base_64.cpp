#include "base_64.h"
#include "serializable_error.h"
#include "mbedtls/base64.h"

namespace helloworld {

std::vector<unsigned char> Base64::encode(const std::vector<unsigned char>& message) {
    size_t requiredSize;
    mbedtls_base64_encode(nullptr, 0, &requiredSize, message.data(), message.size());

    size_t actualLength;
    //unsigned char encoded[requiredSize];
    std::vector<unsigned char> encoded(requiredSize);
    if (mbedtls_base64_encode(encoded.data(), requiredSize, &actualLength, message.data(), message.size()) != 0) {
        throw Error("The buffer size provided for Base64 encoder is too small.");
    }
    encoded.resize(actualLength);
    return encoded;
}

std::vector<unsigned char> Base64::decode(const std::vector<unsigned char>& data) {
    size_t requiredSize;
    mbedtls_base64_encode(nullptr, 0, &requiredSize, data.data(), data.size());

    size_t actualLength;
    std::vector<unsigned char> decoded(requiredSize);
    switch (mbedtls_base64_decode(decoded.data(), requiredSize, &actualLength, data.data(), data.size())) {
        case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
            throw Error("The buffer size provided for Base64 encoder is insufficient.");
        case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
            throw Error("Invalid Base64 conversion: invalid character.");
        default:
            decoded.resize(actualLength);
    }

    return decoded;
}

} // namespace helloworld
