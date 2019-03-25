#include "base_64.h"
#include "serializable_error.h"
#include "mbedtls/base64.h"
#include "utils.h"

namespace helloworld {

std::vector<unsigned char> Base64::encode(const std::vector<unsigned char> &message) {
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

std::vector<unsigned char> Base64::decode(const std::vector<unsigned char> &data) {
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

void Base64::fromStream(std::istream &toEncode, std::ostream &out) {
    while (toEncode.good()) {
        unsigned char buffer[256];
        size_t read = read_n(toEncode, buffer, 256);

        size_t requiredSize;
        mbedtls_base64_encode(nullptr, 0, &requiredSize, buffer, read);

        size_t actualLength;
        std::vector<unsigned char> encoded(requiredSize);
        if (mbedtls_base64_encode(encoded.data(), requiredSize, &actualLength, buffer, read) != 0) {
            throw Error("The buffer size provided for Base64 encoder is too small.");
        }
        write_n(out, encoded.data(), actualLength);
        out << '\n';
    }
}

void Base64::toStream(std::istream &toDecode, std::ostream &out) {
    std::string chunk;
    while (std::getline(toDecode, chunk)) {
        size_t requiredSize;
        mbedtls_base64_decode(nullptr, 0, &requiredSize,
                              reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());

        size_t actualLength;
        std::vector<unsigned char> decoded(requiredSize);
        switch (mbedtls_base64_decode(decoded.data(), requiredSize, &actualLength,
                reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size())) {
            case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
                throw Error("The buffer size provided for Base64 encoder is insufficient.");
            case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
                throw Error("Invalid Base64 conversion: invalid character.");
            default:
                break;
        }
        write_n(out, decoded.data(), actualLength);
    }
}

} // namespace helloworld
