/**
 * @file curve_25519.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief mbedTLS wrapper for ECDH 25519
 * @version 0.1
 * @date 29. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_CURVE_25519_H_
#define HELLOWORLD_SHARED_CURVE_25519_H_

#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include "mbedtls/ecdh.h"

#include "aes_128.h"
#include "sha_512.h"
#include "utils.h"
#include "asymmetric_cipher.h"

namespace helloworld {

class C25519KeyGen : AsymmetricKeyGen {
    static constexpr int BIGINTSIZE = 32;

    unsigned char _buffer_private[BIGINTSIZE]{};
    unsigned char _buffer_public[BIGINTSIZE * 2]{};

public:

    C25519KeyGen();

    // Copying is not available
    C25519KeyGen(const C25519KeyGen &other) = delete;

    C25519KeyGen &operator=(const C25519KeyGen &other) = delete;

    ~C25519KeyGen() override {
        clear<unsigned char>(_buffer_private, BIGINTSIZE);
    }

    bool savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) override;

    bool savePrivateKeyPassword(const std::string &filename, const std::string &pwd) override;

    bool savePublicKey(const std::string &filename) const override;

    std::vector<unsigned char> getPublicKey() const override;

    static std::string getHexPwd(const std::string &pwd) {
        return SHA512{}.getHex(pwd).substr(0, 32);
    }

    static std::string getHexIv(const std::string &pwd) {
        return SHA512{}.getHex(pwd).substr(30, 32);
    }

    static void mpiToByteArray(const mbedtls_mpi *bigInt, unsigned char *buffer, size_t len) {
        //big integer saved as int.n times value on int.p pointer
        if (mbedtls_mpi_write_binary(bigInt, buffer, len) != 0) {
            throw Error("Failed to write big integer value into buffer.");
        }
    }

    static void mpiFromByteArray(mbedtls_mpi *bigInt, const unsigned char *buffer, size_t len) {
        if (mbedtls_mpi_read_binary(bigInt, buffer, len) != 0) {
            throw Error("Failed to read big integer value from buffer.");
        }
    }
};


class C25519 : public AsymmetricCipher {
    static constexpr int BIGINTSIZE = 32;

    friend C25519KeyGen;
    Random _random;
    mbedtls_ecdh_context _context;
    unsigned char _flags;

public:
    explicit C25519();

    ~C25519() override {
        mbedtls_ecdh_free(&_context);
    }

    /**
     * Set the public key of an opposite side (peer)
     *
     * @param key peer's public key
     */
    void setPeerPublicKey(const std::vector<unsigned char> &key);

    /**
     * Load public key of an opposite side (peer) from file
     *
     * @param key file that contains peer's public key
     */
    void loadPeerPublicKey(const std::string &keyFile);

    //this method is implemented, but not needed for DH, as the public key is loaded by the other user
    void setPublicKey(const std::vector<unsigned char> &key) override;

    //this method is implemented, but not needed for DH, as the public key is loaded by the other user
    void loadPublicKey(const std::string &keyFile) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &pwd) override;

    /**
     * Compute DH value from keys loaded in context
     *
     * @return shared secret based on peer's public key &
     */
    std::vector<unsigned char> getShared();


    /*
     * BASIC ASYMMETRIC ENCRYPTION NOT SUPPORTED
     */

    std::vector<unsigned char> encrypt(const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

    std::vector<unsigned char> decrypt(const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

    std::vector<unsigned char> sign(const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

    std::vector<unsigned char> sign(const std::string &) override {
        throw std::runtime_error("Not supported");
    }

    bool verify(const std::vector<unsigned char> &, const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

    bool verify(const std::vector<unsigned char> &, const std::string &) override {
        throw std::runtime_error("Not supported");
    }

private:
    bool _valid();

    void _setup(KeyType type);
};

} //namespace helloworld


#endif //HELLOWORLD_CURVE_25519_H