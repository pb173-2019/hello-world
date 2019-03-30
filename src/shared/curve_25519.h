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

#include "xeddsa/xeddsa.h"

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

    static constexpr int XEDDSA_RAND_LEN = 64;
    static constexpr int XEDDSA_SIGN_LEN = 64;

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

    std::vector<unsigned char> sign(const std::vector<unsigned char> &msg) override {
        if ((_flags & 0x01) != 0x01)
            throw Error("Could not sign data: private key not set.");
        std::vector<unsigned char> output(XEDDSA_SIGN_LEN);

        std::vector<unsigned char> random = _random.get(XEDDSA_RAND_LEN);
        std::vector<unsigned char> privateKey(BIGINTSIZE);
        mbedtls_mpi_write_binary(&_context.d, privateKey.data(), privateKey.size());
        if (xed25519_sign(output.data(), privateKey.data(), msg.data(), msg.size(), random.data()) != 0) {
            throw Error("Failed to create signature.");
        }
        return output;
    }

    std::vector<unsigned char> sign(const std::string &msg) override {
        //todo message doesn't have to be in hex string (e.g. we assume the input is hex string)
        std::vector<unsigned char> data = from_hex(msg);
        return sign(data);
    }

    bool verify(const std::vector<unsigned char> &signature, const std::vector<unsigned char> &msg) override {
        if ((_flags & 0x02) != 0x02)
            throw Error("Could not verify signature: public key not set.");
        if (signature.size() != XEDDSA_SIGN_LEN)
            throw Error("Invalid signature length.");
        std::vector<unsigned char> publicKey(BIGINTSIZE);
        mbedtls_mpi_write_binary(&_context.Qp.X, publicKey.data(), publicKey.size());

        return xed25519_verify(signature.data(), publicKey.data(), msg.data(), msg.size()) == 0;
    }

    bool verify(const std::vector<unsigned char> &signature, const std::string &msg) override {
        std::vector<unsigned char> data = from_hex(msg);
        return verify(signature, data);
    }

private:
    bool _valid();

    void _setup(KeyType type);

    //compute hash_1 -> use 0xFE
    std::vector<unsigned char> hash_1(const mbedtls_mpi& X);
    std::vector<unsigned char> hash(const mbedtls_mpi& X);
    /**
     * Calculate twisted edward curve keypair
     * @param A bigint to fill with private key
     * @param a bigint to fill with public key
     * @param d x25519 private key
     */
    void getTwistedEdwardKeyPaird(mbedtls_mpi& A, mbedtls_mpi& a, const mbedtls_mpi& d);
};

} //namespace helloworld


#endif //HELLOWORLD_CURVE_25519_H
