/**
 * @file rsa_2048.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief RSA 2048 wrapper
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_RSA_2048_H_
#define HELLOWORLD_SHARED_RSA_2048_H_

#include <vector>

#include "asymmetric_cipher.h"
#include "random.h"

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

#define MBEDTLS_PK_PARSE_C

namespace helloworld {

class RSAKeyGen : AsymmetricKeyGen {
    unsigned char _buffer_private[MBEDTLS_MPI_MAX_SIZE * 2];
    size_t _priv_olen;
    unsigned char _buffer_public[MBEDTLS_MPI_MAX_SIZE];
    size_t _pub_olen;

public:
    RSAKeyGen();

    // Copying is not available
    RSAKeyGen(const RSAKeyGen &other) = delete;

    RSAKeyGen &operator=(const RSAKeyGen &other) = delete;

    ~RSAKeyGen() override;

    bool savePrivateKey(const std::string &filename, const std::string &key, const std::string& iv) override;

    bool savePublicKey(const std::string &filename) const override;

    std::vector<unsigned char> getPublicKey() const override {
        return std::vector<unsigned char>(_buffer_public, _buffer_public + _pub_olen);
    }

private:
    size_t _getKeyLength(const unsigned char *key, int len, const std::string &terminator);
};

enum class KeyType {
    PUBLIC_KEY, PRIVATE_KEY, NO_KEY
};

class RSA2048 : public AsymmetricCipher {
    friend RSAKeyGen;

    mbedtls_pk_context _context{};
    mbedtls_rsa_context* _basic_context;

    KeyType _keyLoaded = KeyType::NO_KEY;
    bool _dirty = false;

public:
    const static int KEY_SIZE = 2048;
    const static int EXPONENT = 65537;

    explicit RSA2048();

    ~RSA2048() override {
        mbedtls_pk_free(&_context);
    }

    void setPublicKey(std::vector<unsigned char>& key) override;

    void loadPublicKey(const std::string &keyFile) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string& iv) override;

    std::vector<unsigned char> encrypt(const std::string &msg) override;

    std::string decrypt(const std::vector<unsigned char> &data) override;

    std::vector<unsigned char> sign(const std::string &hash) override;

    bool verify(const std::vector<unsigned char> &signedData, const std::string &hash) override;

private:

    bool _valid(KeyType keyNeeded) {
        return mbedtls_pk_can_do(&_context, MBEDTLS_PK_RSA) == 1 && _keyLoaded == keyNeeded && !_dirty;
    }

    void _setup(KeyType type);

    void _loadKeyFromStream(std::istream& input);
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_RSA_2048_H_
