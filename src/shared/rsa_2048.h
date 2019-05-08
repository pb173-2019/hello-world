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
#include "sha_512.h"

#define MBEDTLS_PK_PARSE_C

namespace helloworld {

class RSAKeyGen : AsymmetricKeyGen {
    unsigned char _buffer_private[MBEDTLS_MPI_MAX_SIZE * 2];
    size_t _priv_olen;
    unsigned char _buffer_public[MBEDTLS_MPI_MAX_SIZE];
    size_t _pub_olen;

    Random random;

   public:
    RSAKeyGen();

    // Copying is not available
    RSAKeyGen(const RSAKeyGen &other) = delete;

    RSAKeyGen &operator=(const RSAKeyGen &other) = delete;

    ~RSAKeyGen() override;

    bool savePrivateKey(const std::string &filename, const zero::str_t &key,
                        const std::string &iv) override;

    bool savePrivateKeyPassword(const std::string &filename,
                                const zero::str_t &pwd) override;

    bool savePublicKey(const std::string &filename) const override;

    zero::bytes_t getPublicKey() const override {
        return zero::bytes_t(_buffer_public, _buffer_public + _pub_olen);
    }

    static zero::str_t getHexPwd(const zero::str_t &pwd) {
        return SHA512{}.getSafeHex(pwd).substr(0, 32);
    }

    static std::string getHexIv(const zero::str_t &pwd) {
        return SHA512{}.getHex(pwd).substr(30, 32);
    }

   private:
    size_t _getKeyLength(const unsigned char *key, size_t len,
                         const std::string &terminator);
};

class RSA2048 : public AsymmetricCipher {
    friend RSAKeyGen;

    mbedtls_pk_context _context{};
    mbedtls_rsa_context *_basic_context;

    KeyType _keyLoaded = KeyType::NO_KEY;
    Random random;

   public:
    const static int KEY_SIZE = 2048;
    const static int EXPONENT = 65537;
    const static int BLOCK_SIZE_OAEP = 256;

    explicit RSA2048();

    ~RSA2048() override { mbedtls_pk_free(&_context); }

    void setPublicKey(const zero::bytes_t &key) override;

    void loadPublicKey(const std::string &keyFile) override;

    /**
     * Expects key & iv exactly 32 chars in hex (e.g. 16 bytes) long
     * @param keyFile file to load
     * @param key key for aes to decrypt
     * @param iv iv for aes to decrypt
     */
    void loadPrivateKey(const std::string &keyFile, const zero::str_t &key,
                        const std::string &iv) override;

    void loadPrivateKey(const std::string &keyFile,
                        const zero::str_t &pwd) override;

    std::vector<unsigned char> encrypt(
        const std::vector<unsigned char> &msg) override;
    std::vector<unsigned char> encryptKey(const zero::bytes_t &key);

    std::vector<unsigned char> decrypt(
        const std::vector<unsigned char> &data) override;
    zero::bytes_t decryptKey(const std::vector<unsigned char> &data);

    std::vector<unsigned char> sign(
        const std::vector<unsigned char> &hash) override;
    std::vector<unsigned char> sign(const std::string &hash) override;

    bool verify(const std::vector<unsigned char> &signedData,
                const std::vector<unsigned char> &hash) override;
    bool verify(const std::vector<unsigned char> &signedData,
                const std::string &hash) override;

   private:
    bool _valid(KeyType keyNeeded) {
        return mbedtls_pk_can_do(&_context, MBEDTLS_PK_RSA) == 1 &&
               _keyLoaded == keyNeeded;
    }

    void _setup(KeyType type);

    void _loadKeyFromStream(std::istream &input);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_RSA_2048_H_
