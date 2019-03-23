#include "rsa_2048.h"

#include <fstream>
#include <memory>
#include <sstream>

#include "utils.h"
#include "aes_128.h"
#include "sha_512.h"
#include "serializable_error.h"

namespace helloworld {

RSAKeyGen::RSAKeyGen() {
    RSA2048 rsa{};
    Random random{};
    mbedtls_ctr_drbg_context *random_ctx = random.getEngine();

    if (mbedtls_pk_setup(&rsa._context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        throw Error("Could not initialize RSA ciper.");
    }
    auto *inner_ctx = reinterpret_cast<mbedtls_rsa_context *>(rsa._context.pk_ctx);
    //set OAEP padding
    mbedtls_rsa_set_padding(inner_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);

    if (mbedtls_rsa_gen_key(inner_ctx, mbedtls_ctr_drbg_random, random_ctx,
                            RSA2048::KEY_SIZE, RSA2048::EXPONENT) != 0) {
        throw Error("RSA key generating failed.");
    }

    if (mbedtls_pk_write_pubkey_pem(&rsa._context, _buffer_public, MBEDTLS_MPI_MAX_SIZE) != 0) {
        throw Error("Could not load pem format for public key.");
    }
    _pub_olen = _getKeyLength(_buffer_public, MBEDTLS_MPI_MAX_SIZE, "-----END PUBLIC KEY-----\n");

    if (mbedtls_pk_write_key_pem(&rsa._context, _buffer_private, MBEDTLS_MPI_MAX_SIZE * 2) != 0) {
        throw Error("Could not load pem format for private key.");
    }
    _priv_olen = _getKeyLength(_buffer_private, MBEDTLS_MPI_MAX_SIZE * 2, "-----END RSA PRIVATE KEY-----\n");
}

bool RSAKeyGen::savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) {
    std::ofstream out_pri{filename, std::ios::out | std::ios::binary};
    if (!out_pri)
        return false;

    if (_priv_olen == 0) return false;

    if (!key.empty()) {
        std::stringstream keystream{};
        AES128 cipher{};
        write_n(keystream, _buffer_private, _priv_olen);
        cipher.setKey(key);
        cipher.setIv(iv);
        cipher.encrypt(keystream, out_pri);
    } else {
        write_n(out_pri, _buffer_private, _priv_olen);
    }
    return true;
}

bool RSAKeyGen::savePublicKey(const std::string &filename) const {
    std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
    if (!out_pub)
        return false;

    if (_pub_olen == 0) return false;
    write_n(out_pub, _buffer_public, _pub_olen);
    return true;
}

size_t RSAKeyGen::_getKeyLength(const unsigned char *key, int len, const std::string &terminator) {
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
    clear<unsigned char>(_buffer_private, MBEDTLS_MPI_MAX_SIZE * 2);
    clear<unsigned char>(_buffer_public, MBEDTLS_MPI_MAX_SIZE);
}

RSA2048::RSA2048() {
    mbedtls_pk_init(&_context);
}

void RSA2048::loadPublicKey(const std::string &keyFile) {
    if (_keyLoaded != KeyType::NO_KEY)
        return;

    if (mbedtls_pk_parse_public_keyfile(&_context, keyFile.c_str()) != 0) {
        throw Error("Could not read public key.");
    }
    _setup(KeyType::PUBLIC_KEY);
}

void RSA2048::setPublicKey(std::vector<unsigned char> &key) {
    key.push_back(static_cast<unsigned char>('\0')); //mbedtls expecting null terminator
    if (mbedtls_pk_parse_public_key(&_context, key.data(), key.size()) != 0) {
        throw Error("Could not load public key from vector.");
    }
    _setup(KeyType::PUBLIC_KEY);
}

void RSA2048::loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) {
    if (_keyLoaded != KeyType::NO_KEY)
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
        _loadKeyFromStream(decrypted);
    } else {
        _loadKeyFromStream(input);
    }
    _setup(KeyType::PRIVATE_KEY);
}

std::vector<unsigned char> RSA2048::encrypt(const std::string &msg) {
    if (!_valid(KeyType::PUBLIC_KEY))
        throw Error("RSA not initialized properly.");

    Random random{};
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    //label ignored
    if (mbedtls_rsa_rsaes_oaep_encrypt(_basic_context, mbedtls_ctr_drbg_random,
                                       random.getEngine(), MBEDTLS_RSA_PUBLIC, nullptr, 0, msg.size(),
                                       reinterpret_cast<const unsigned char *>(msg.c_str()), buf) != 0) {

        throw Error("Failed to encrypt data.");
    }
    return std::vector<unsigned char>(buf, buf + _basic_context->len);
}

std::string RSA2048::decrypt(const std::vector<unsigned char> &data) {
    if (!_valid(KeyType::PRIVATE_KEY))
        throw Error("RSA not initialized properly.");

    Random random{};
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    if (mbedtls_rsa_rsaes_oaep_decrypt(_basic_context, mbedtls_ctr_drbg_random,
                                       random.getEngine(), MBEDTLS_RSA_PRIVATE, nullptr, 0, &olen, data.data(), buf,
                                       MBEDTLS_MPI_MAX_SIZE) != 0) {

        throw Error("Failed to encrypt data.");
    }
    return std::string(reinterpret_cast<char *>(buf), reinterpret_cast<char *>(buf) + olen);
}

std::vector<unsigned char> RSA2048::sign(const std::string &hash) {
    if (!_valid(KeyType::PRIVATE_KEY))
        throw Error("RSA not instantiated properly for signature.");

    std::vector<unsigned char> hash_bytes = from_hex(hash);
    std::vector<unsigned char> signature(_basic_context->len);
    size_t olen;
    Random random{};

    if (mbedtls_pk_sign(&_context, MBEDTLS_MD_SHA512, hash_bytes.data(), hash_bytes.size(),
                        signature.data(), &olen, mbedtls_ctr_drbg_random, random.getEngine()) != 0) {
        throw Error("Failed to create signature.");
    }
    return signature;
}

bool RSA2048::verify(const std::vector<unsigned char> &signedData,
                     const std::string &hash) {
    if (!_valid(KeyType::PUBLIC_KEY))
        throw Error("RSA not instantiated properly for verification.");

    std::vector<unsigned char> hash_bytes = from_hex(hash);
    return mbedtls_pk_verify_ext(MBEDTLS_PK_RSA, nullptr, &_context, MBEDTLS_MD_SHA512,
                                 hash_bytes.data(), hash_bytes.size(),
                                 signedData.data(), signedData.size()) == 0;
}

void RSA2048::_setup(KeyType type) {
    _basic_context = reinterpret_cast<mbedtls_rsa_context *>(_context.pk_ctx);
    mbedtls_rsa_set_padding(_basic_context, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA512);
    _keyLoaded = type;
}

void RSA2048::_loadKeyFromStream(std::istream &input) {
    size_t length = getSize(input) + 1;
    std::vector<unsigned char> buff(length);
    read_n(input, buff.data(), length - 1);
    buff[length - 1] = '\0'; //mbedtls_pk_parse_key expecting null terminator

    if (mbedtls_pk_parse_key(&_context, buff.data(), length, nullptr, 0) != 0) {
        throw Error("Could not load private key from stream.");
    }
    clear<unsigned char>(buff.data(), length);
}

} //namespace helloworld

