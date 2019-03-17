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
    unsigned char buffer_private[MBEDTLS_MPI_MAX_SIZE * 2];
    size_t priv_olen;
    unsigned char buffer_public[MBEDTLS_MPI_MAX_SIZE];
    size_t pub_olen;
    
public:
    RSAKeyGen();

    // Copying is not available
    RSAKeyGen(const RSAKeyGen &other) = delete;

    RSAKeyGen &operator=(const RSAKeyGen &other) = delete;

    ~RSAKeyGen() override;

    /**
     * Save public key into file in perm format
     * @param filename filename to save to
     * @param key AES key to encrypt the private key, if empty string,
     *        the key is saved as plaintext
     * @param iv AES iv for encryption
     * @return true if successfully saved
     */
    bool savePrivateKey(const std::string &filename, const std::string &key, const std::string& iv) override;

    /**
     * Save public key into file in perm format
     * @param filename filename to save to
     * @return true if successfully saved
     */
    bool savePublicKey(const std::string &filename) override;
    
    /**
     * Return copy of the public key. Copy of private key is not supported
     * 
     * @return  std::vector<unsigned char> copy of public key
     */
    std::vector<unsigned char> getPublicKey() {
        return std::vector<unsigned char>(buffer_public, buffer_public + pub_olen);
    }

private:
    size_t getKeyLength(const unsigned char *key, int len, const std::string &terminator);
};

enum class KeyType {
    PUBLIC_KEY, PRIVATE_KEY, NO_KEY
};

class RSA2048 : public AsymmetricCipher {
    friend RSAKeyGen;
    const static int KEY_SIZE = 2048;
    const static int EXPONENT = 65537;

    mbedtls_pk_context context{};
    mbedtls_rsa_context* basic_context;

    KeyType keyLoaded = KeyType::NO_KEY;
    bool dirty = false;

public:
    explicit RSA2048();

    ~RSA2048() override {
        mbedtls_pk_free(&context);
    }

    void loadPublicKey(const std::string &keyFile) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string& iv) override;
    
    void setPublicKey(std::vector<unsigned char>& key);

    std::vector<unsigned char> encrypt(const std::string &msg) override;

    std::string decrypt(const std::vector<unsigned char> &data) override;

    std::vector<unsigned char> sign(const std::string &hash) override;

    bool verify(const std::vector<unsigned char> &signedData, const std::string &hash) override;

private:

    bool valid(KeyType keyNeeded) {
        return mbedtls_pk_can_do(&context, MBEDTLS_PK_RSA) == 1 && keyLoaded == keyNeeded && !dirty;
    }

    void setup(KeyType type);

    void loadKeyFromStream(std::istream& input);
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_RSA_2048_H_
