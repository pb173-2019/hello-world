#include "rsa_2048.h"

#include <fstream>
#include <stdexcept>
#include <memory>
#include <sstream>

#include "utils.h"
#include "aes_128.h"
#include "sha_512.h"

namespace helloworld {

RSAKeyGen::RSAKeyGen() {
    RSA2048 rsa{};
    if (mbedtls_pk_setup(&rsa.context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        throw std::runtime_error("Could not initialize RSA ciper.");
    }
    auto *inner_ctx = reinterpret_cast<mbedtls_rsa_context *>(rsa.context.pk_ctx);
    //set OAEP padding
    mbedtls_rsa_set_padding(inner_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);

    if (mbedtls_rsa_gen_key(inner_ctx, mbedtls_ctr_drbg_random, random_ctx,
            RSA2048::KEY_SIZE, RSA2048::EXPONENT) != 0) {
        throw std::runtime_error("RSA key generating failed.");
    }

    if (mbedtls_pk_write_pubkey_pem(&rsa.context, buffer_public, MBEDTLS_MPI_MAX_SIZE) != 0) {
        throw std::runtime_error("Could not load pem format for public key.");
    }

    if (mbedtls_pk_write_key_pem(&rsa.context, buffer_private, MBEDTLS_MPI_MAX_SIZE * 2) != 0) {
        throw std::runtime_error("Could not load pem format for private key.");
    }
}

bool RSAKeyGen::savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) {
    std::ofstream out_pri{filename, std::ios::out | std::ios::binary};
    if (!out_pri)
        return false;

    size_t keylen = getKeyLength(buffer_private, MBEDTLS_MPI_MAX_SIZE * 2, "-----END RSA PRIVATE KEY-----\n");
    if (keylen == 0) return false;

    if (!key.empty()) {
        std::stringstream keystream{};
        AES128 cipher{};
        write_n(keystream, buffer_private, keylen);
        cipher.setKey(key);
        cipher.setIv(iv);
        cipher.encrypt(keystream, out_pri);
    } else {
        write_n(out_pri, buffer_private, keylen);
    }
    return true;
}

bool RSAKeyGen::savePublicKey(const std::string &filename) {
    std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
    if (!out_pub)
        return false;

    size_t keylen = getKeyLength(buffer_public, MBEDTLS_MPI_MAX_SIZE, "-----END PUBLIC KEY-----\n");
    if (keylen == 0) return false;
    write_n(out_pub, buffer_public, keylen);
    return true;
}

size_t RSAKeyGen::getKeyLength(const unsigned char *key, int len, const std::string &terminator) {
    size_t strIdx = 0;
    size_t keyIdx = 300;
    while (keyIdx < len) {
        if (key[keyIdx] == terminator[strIdx]) {
            ++strIdx;
        } else {
            strIdx = 0;
        }
        ++keyIdx;

        if (strIdx >= terminator.size())
            return keyIdx;
    }
    return 0;
}

RSAKeyGen::~RSAKeyGen() {
    clear<unsigned char>(buffer_private, MBEDTLS_MPI_MAX_SIZE * 2);
    clear<unsigned char>(buffer_public, MBEDTLS_MPI_MAX_SIZE);
}

RSA2048::RSA2048() {
    mbedtls_pk_init(&context);
}

void RSA2048::loadPublicKey(const std::string &keyFile) {
    if (keyLoaded != KeyType::NO_KEY)
        return;

    if (mbedtls_pk_parse_public_keyfile(&context, keyFile.c_str()) != 0) {
        throw std::runtime_error("Could not read public key.");
    }
    setup(KeyType::PUBLIC_KEY);
}

void RSA2048::loadKeyFromStream(std::istream& input) {
    size_t length = getSize(input);
    unsigned char buff[length + 1];
    read_n(input, buff, length);
    buff[length] = '\0'; //mbedtls_pk_parse_key expecting null terminator

    if (mbedtls_pk_parse_key(&context, buff, length + 1, nullptr, 0) != 0) {
        throw std::runtime_error("Could not load private key from stream.");
    }
}

void RSA2048::loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string& iv) {
    if (keyLoaded != KeyType::NO_KEY)
        return;

    std::ifstream input{keyFile, std::ios::in | std::ios::binary};
    if (!input)
        return;

    if (!key.empty()) {
        std::stringstream decrypted;
        AES128 cipher;
        cipher.setIv(iv);
        cipher.setKey(key);
        cipher.decrypt(input, decrypted);
        loadKeyFromStream(decrypted);
    } else {
        loadKeyFromStream(input);
    }
    setup(KeyType::PRIVATE_KEY);
}

void RSA2048::setup(KeyType type) {
    basic_context = reinterpret_cast<mbedtls_rsa_context *>(context.pk_ctx);
    mbedtls_rsa_set_padding(basic_context, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);
    keyLoaded = type;
}

std::vector<unsigned char> RSA2048::encrypt(const std::string &msg) {
    if (!valid(KeyType::PUBLIC_KEY))
        throw std::runtime_error("RSA not initialized properly.");

    Random random{};
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    //label ignored
    if (mbedtls_rsa_rsaes_oaep_encrypt(basic_context, mbedtls_ctr_drbg_random,
                                       random.getEngine(), MBEDTLS_RSA_PUBLIC, nullptr, 0, msg.size(),
                                       reinterpret_cast<const unsigned char *>(msg.c_str()), buf) != 0) {

        throw std::runtime_error("Failed to encrypt data.");
    }
    dirty = true;
    return std::vector<unsigned char>(buf, buf + basic_context->len);
}

std::string RSA2048::decrypt(const std::vector<unsigned char> &data) {
    if (!valid(KeyType::PRIVATE_KEY))
        throw std::runtime_error("RSA not initialized properly.");

    Random random{};
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    if (mbedtls_rsa_rsaes_oaep_decrypt(basic_context, mbedtls_ctr_drbg_random,
                                       random.getEngine(), MBEDTLS_RSA_PRIVATE, nullptr, 0, &olen, data.data(), buf,
                                       MBEDTLS_MPI_MAX_SIZE) != 0) {

        throw std::runtime_error("Failed to encrypt data.");
    }
    dirty = true;
    return std::string(reinterpret_cast<char *>(buf), reinterpret_cast<char *>(buf) + olen);
}

std::vector<unsigned char> RSA2048::sign(const std::string &hash) {
    if (!valid(KeyType::PRIVATE_KEY))
        throw std::runtime_error("RSA not instantiated properly for signature.");

    std::vector<unsigned char> hash_bytes = from_hex(hash);
    unsigned char signature[basic_context->len];
    size_t olen;
    Random random{};

    if (mbedtls_pk_sign(&context, MBEDTLS_MD_SHA512, hash_bytes.data(), hash_bytes.size(),
                        signature, &olen, mbedtls_ctr_drbg_random, random.getEngine()) != 0) {
        throw std::runtime_error("Failed to create signature.");
    }
    return std::vector<unsigned char>(signature, signature + olen);
}

bool RSA2048::verify(const std::vector<unsigned char> &signedData,
                     const std::string &hash) {
    if (!valid(KeyType::PUBLIC_KEY))
        throw std::runtime_error("RSA not instantiated properly for verification.");

    std::vector<unsigned char> hash_bytes = from_hex(hash);
    return mbedtls_pk_verify_ext(MBEDTLS_PK_RSA, nullptr, &context, MBEDTLS_MD_SHA512,
                                 hash_bytes.data(), hash_bytes.size(),
                                 signedData.data(), signedData.size()) == 0;
}

} //namespace helloworld

