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

class C25519;

class C25519KeyGen : AsymmetricKeyGen {
    friend C25519;
    static constexpr int KEY_BYTES_LEN = 32;

    std::vector<unsigned char> _buffer_private;
    std::vector<unsigned char> _buffer_public;

public:

    C25519KeyGen();

    // Copying is not available
    C25519KeyGen(const C25519KeyGen &other) = delete;

    C25519KeyGen &operator=(const C25519KeyGen &other) = delete;

    ~C25519KeyGen() override {
        clear<unsigned char>(_buffer_private.data(), KEY_BYTES_LEN);
    }

    bool savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) override;

    bool savePrivateKeyPassword(const std::string &filename, const std::string &pwd) override;

    bool savePublicKey(const std::string &filename) const override;

    std::vector<unsigned char> getPublicKey() const override;

    std::vector<unsigned char> getPrivateKey() const;

    static std::string getHexPwd(const std::string &pwd) {
        return SHA512{}.getHex(pwd).substr(0, 32);
    }

    static std::string getHexIv(const std::string &pwd) {
        return SHA512{}.getHex(pwd).substr(30, 32);
    }
};


class C25519 : public AsymmetricCipher {

    std::vector<unsigned char> _buffer_private;
    std::vector<unsigned char> _buffer_public;

    static constexpr int XEDDSA_RAND_LEN = 64;
    static constexpr int XEDDSA_SIGN_LEN = 64;


    Random _random;
    unsigned char _flags = 0x00;

public:
    // Just for key bundle
    // Might replace XEDSA_SIGN_LEN so it can be used generaly for SFINAE
    static constexpr int SIGN_BYTES_LEN = 64;
    static constexpr int KEY_BYTES_LEN = 32;

    explicit C25519();

    ~C25519() override {
        if (!_buffer_private.empty())
            clear<unsigned char>(_buffer_private.data(), KEY_BYTES_LEN);
    }

    /**
     * X3DH purpose easy setter
     */
    void setPrivateKey(const C25519KeyGen &keys) {
        _buffer_private = keys._buffer_private;
        _setup(KeyType::PRIVATE_KEY);
    }

    /**
     * X3DH purpose easy setter
     */
    void setPublicKey(const C25519KeyGen &keys) {
        _buffer_private = keys._buffer_public;
        _setup(KeyType::PUBLIC_KEY);

    }

    /**
     * Compute the second step of DH (the first is generating the public key)
     * @return shared secret
     */
    std::vector<unsigned char> getShared();

    //this method is implemented, but not needed for DH, as the public key is loaded by the other user
    void setPublicKey(const std::vector<unsigned char> &key) override;

    //this method is implemented, but not needed for DH, as the public key is loaded by the other user
    void loadPublicKey(const std::string &keyFile) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) override;

    void loadPrivateKey(const std::string &keyFile, const std::string &pwd) override;

    std::vector<unsigned char> sign(const std::vector<unsigned char> &msg) override;

    std::vector<unsigned char> sign(const std::string &msg) override;

    bool verify(const std::vector<unsigned char> &signature, const std::vector<unsigned char> &msg) override;

    bool verify(const std::vector<unsigned char> &signature, const std::string &msg) override;

    /*
     * BASIC ASYMMETRIC ENCRYPTION NOT SUPPORTED
     */

    std::vector<unsigned char> encrypt(const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

    std::vector<unsigned char> decrypt(const std::vector<unsigned char> &) override {
        throw std::runtime_error("Not supported");
    }

private:
    bool _valid();

    void _setup(KeyType type);

};

} //namespace helloworld


#endif //HELLOWORLD_CURVE_25519_H
