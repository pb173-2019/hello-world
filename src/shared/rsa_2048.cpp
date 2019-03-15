#include "rsa_2048.h"

#include <cmath>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "utils.h"

namespace helloworld {

    RSAKeyGen::RSAKeyGen() {
        RSA2048 context{};
        if (mbedtls_pk_setup(&context.key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
            throw std::runtime_error("Could not initialize RSA ciper.");
        }
        auto* inner_ctx = reinterpret_cast<mbedtls_rsa_context *>(context.key.pk_ctx);
        //set OAEP padding
        mbedtls_rsa_set_padding(inner_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);

        if (mbedtls_rsa_gen_key(inner_ctx, mbedtls_ctr_drbg_random, random_ctx, RSA2048::KEY_SIZE, RSA2048::EXPONENT) != 0) {
            throw std::runtime_error("RSA key generating failed.");
        }

        if (mbedtls_pk_write_pubkey_pem(&context.key, buffer_public, MBEDTLS_MPI_MAX_SIZE) != 0) {
            throw std::runtime_error("Could not load pem format for public key.");
        }

        if (mbedtls_pk_write_key_pem(&context.key, buffer_private, MBEDTLS_MPI_MAX_SIZE * 2) != 0) {
            throw std::runtime_error("Could not load pem format for private key.");
        }
    }

    bool RSAKeyGen::savePrivateKey(const std::string &filename, const std::string &pwd) {
        std::ofstream out_pri{filename, std::ios::binary};
        if (!out_pri)
            return false;

        int keylen = getKeyLength(buffer_private, MBEDTLS_MPI_MAX_SIZE * 2, "-----END RSA PRIVATE KEY-----\n");
        if (keylen == 0) return false;

        //todo hash with pwd

        out_pri.write(reinterpret_cast<char *>(buffer_private), keylen);
    }

    bool RSAKeyGen::savePublicKey(const std::string &filename) {
        std::ofstream out_pub{filename, std::ios::binary};
        if (!out_pub)
            return false;

        int keylen = getKeyLength(buffer_public, MBEDTLS_MPI_MAX_SIZE, "-----END PUBLIC KEY-----\n");
        if (keylen == 0) return false;
        out_pub.write(reinterpret_cast<char *>(buffer_public), keylen);
    }

    int RSAKeyGen::getKeyLength(const unsigned char *key, int len, const std::string &terminator) {
        int strIdx = 0;
        int keyIdx = 300;
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
        mbedtls_pk_init(&key);
    }


    void RSA2048::loadPublicKey(const std::string &keyFile) {
        if (keyLoaded != KeyType::NO_KEY)
            return;

        if(mbedtls_pk_parse_public_keyfile(&key, keyFile.c_str()) != 0) {
           throw std::runtime_error("Could not read public key.");
        }
        setup(KeyType::PUBLIC_KEY);
    }

    void RSA2048::loadPrivateKey(const std::string &keyFile, const std::string */*pwd*/) {
        if (keyLoaded != KeyType::NO_KEY)
            return;

        if(mbedtls_pk_parse_keyfile(&key, keyFile.c_str(), nullptr) != 0) {
            throw std::runtime_error("Could not read public key.");
        }

        //const char* data = (pwd == nullptr) ? nullptr : pwd->c_str();
        //todo decrypt private key

        setup(KeyType::PRIVATE_KEY);
    }

    void RSA2048::setup(KeyType type) {
        basic_context = reinterpret_cast<mbedtls_rsa_context *>(key.pk_ctx);
        mbedtls_rsa_set_padding(basic_context, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);
        keyLoaded = type;
    }

    std::vector<unsigned char> RSA2048::encrypt(const std::string &msg) {
        if (! valid(KeyType::PUBLIC_KEY))
            throw std::runtime_error("RSA not initialized properly.");

        Random random{};
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

        //label ignored
        if(mbedtls_rsa_rsaes_oaep_encrypt(basic_context, mbedtls_ctr_drbg_random,
                random.getEngine(), MBEDTLS_RSA_PUBLIC, nullptr, 0, msg.size(),
                reinterpret_cast<const unsigned char *>(msg.c_str()), buf ) != 0 ) {

            throw std::runtime_error("Failed to encrypt data.");
        }
        dirty = true;
        return std::vector<unsigned char>(buf, buf + basic_context->len);
    }

    std::string RSA2048::decrypt(const std::vector<unsigned char> &data) {
        if (! valid(KeyType::PRIVATE_KEY))
            throw std::runtime_error("RSA not initialized properly.");

        Random random{};
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
        size_t olen = 0;

        if (mbedtls_rsa_rsaes_oaep_decrypt(basic_context, mbedtls_ctr_drbg_random,
                random.getEngine(), MBEDTLS_RSA_PRIVATE, nullptr, 0, &olen, data.data(), buf,
                MBEDTLS_MPI_MAX_SIZE ) != 0 ) {

            throw std::runtime_error("Failed to encrypt data.");
        }
        dirty = true;
        return std::string(reinterpret_cast<char*>(buf), reinterpret_cast<char*>(buf) + olen);
    }

    std::vector<unsigned char> RSA2048::sign(const std::string &hash) {
        return std::vector<unsigned char>();
    }

    bool RSA2048::verify(const std::vector<unsigned char> &signedData,
                         const std::string &hash) {
        return false;
    }
} //namespace helloworld

