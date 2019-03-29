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

    C25519KeyGen() {
        Random random{};

        mbedtls_ecdh_context context;
        mbedtls_ecdh_init(&context);

        if (mbedtls_ecp_group_load(&context.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
            throw Error("Could not load CURVE25519 to context.");
        }

        if (mbedtls_ecdh_gen_public(&context.grp, &context.d, &context.Q,
                                    mbedtls_ctr_drbg_random, random.getEngine()) != 0) {
            throw Error("Failed to generate public key.");
        }

        mpiToByteArray(&context.Q.X, _buffer_public, BIGINTSIZE);
        mpiToByteArray(&context.Q.Y, _buffer_public + BIGINTSIZE, BIGINTSIZE);
        mpiToByteArray(&context.d, _buffer_private, BIGINTSIZE);

        mbedtls_ecdh_free(&context);
    }

    // Copying is not available
    C25519KeyGen(const C25519KeyGen &other) = delete;

    C25519KeyGen &operator=(const C25519KeyGen &other) = delete;

    ~C25519KeyGen() override {
        clear<unsigned char>(_buffer_private, BIGINTSIZE);
    }

    bool savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) override {
        std::ofstream out_pri{filename, std::ios::out | std::ios::binary};
        if (!out_pri)
            return false;

        if (!key.empty()) {
            std::stringstream keystream{};
            AES128 cipher{};
            write_n(keystream, _buffer_private, BIGINTSIZE);
            cipher.setKey(key);
            cipher.setIv(iv);
            cipher.encrypt(keystream, out_pri);
        } else {
            write_n(out_pri, _buffer_private, BIGINTSIZE);
        }
        return true;
    }

    bool savePrivateKeyPassword(const std::string &filename, const std::string &pwd) override {
        return savePrivateKey(filename, getHexPwd(pwd), getHexIv(pwd));
    }

    bool savePublicKey(const std::string &filename) const override {
        std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
        if (!out_pub)
            return false;

        write_n(out_pub, _buffer_public, BIGINTSIZE);
        write_n(out_pub, _buffer_public, BIGINTSIZE);
        return true;
    }

    std::vector<unsigned char> getPublicKey() const override {
        return std::vector<unsigned char>(_buffer_public, _buffer_public + BIGINTSIZE * 2);
    }

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
    explicit C25519() {
        mbedtls_ecdh_init(&_context);

        if (mbedtls_ecp_group_load(&_context.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
            throw Error("Could not load CURVE25519 to context.");
        }
    }

    ~C25519() override {
        mbedtls_ecdh_free(&_context);
    }

    void setPeerPublicKey(const std::vector<unsigned char> &key) {
        if (key.size() != BIGINTSIZE) //works with X only
            throw Error("Invalid c25519 public key.");
        // Z-axis not user, init to 1
        if (mbedtls_mpi_lset(&_context.Qp.Z, 1) != 0) {
            throw Error("Failed to initialize peer's key.");
        }
        C25519KeyGen::mpiFromByteArray(&_context.Qp.X, key.data(), BIGINTSIZE);
        _setup(KeyType::PUBLIC_KEY);
    }

    void loadPeerPublicKey(const std::string &keyFile) {
        std::ifstream input{keyFile, std::ios::in | std::ios::binary};
        if (!input) return;

        std::vector<unsigned char> buffer(BIGINTSIZE);
        read_n(input, buffer.data(), BIGINTSIZE);
        setPublicKey(buffer);
    }

    void setPublicKey(const std::vector<unsigned char> &key) override {
        if (key.size() != BIGINTSIZE * 2) //X & Y axis
            throw Error("Invalid c25519 public key.");
        C25519KeyGen::mpiFromByteArray(&_context.Q.X, key.data(), BIGINTSIZE);
        C25519KeyGen::mpiFromByteArray(&_context.Q.Y, key.data() + BIGINTSIZE, BIGINTSIZE);
        _setup(KeyType::PUBLIC_KEY);
    }

    void loadPublicKey(const std::string &keyFile) override {
        std::ifstream input{keyFile, std::ios::in | std::ios::binary};
        if (!input) return;

        std::vector<unsigned char> buffer(BIGINTSIZE * 2);
        read_n(input, buffer.data(), BIGINTSIZE * 2);
        setPublicKey(buffer);
    }

    /**
     * Expects key & iv exactly 32 chars in hex (e.g. 16 bytes) long
     * @param keyFile file to load
     * @param key key for aes to decrypt
     * @param iv iv for aes to decrypt
     */
    void loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) override {
        std::ifstream input{keyFile, std::ios::in | std::ios::binary};
        if (!input) return;

        std::vector<unsigned char> buffer(BIGINTSIZE);
        if (!key.empty()) {
            std::stringstream decrypted;
            AES128 cipher;
            cipher.setIv(iv);
            cipher.setKey(key);
            cipher.decrypt(input, decrypted);
            read_n(decrypted, buffer.data(), buffer.size());
        } else {
            read_n(input, buffer.data(), buffer.size());
        }
        C25519KeyGen::mpiFromByteArray(&_context.d, buffer.data(), buffer.size());
        _setup(KeyType::PRIVATE_KEY);
        clear<unsigned char>(buffer.data(), buffer.size());
    }

    void loadPrivateKey(const std::string &keyFile, const std::string &pwd) override {
        loadPrivateKey(keyFile, C25519KeyGen::getHexPwd(pwd), C25519KeyGen::getHexIv(pwd));
    }

    std::vector<unsigned char> getShared() {
        if (mbedtls_ecdh_compute_shared( &_context.grp, &_context.z, &_context.Qp, &_context.d,
                mbedtls_ctr_drbg_random, _random.getEngine() ) != 0) {
            throw Error("Could not compute shared secret (ECDH).");
        }
        std::vector<unsigned char> buffer(BIGINTSIZE);
        C25519KeyGen::mpiToByteArray(&_context.z, buffer.data(), BIGINTSIZE);
        return buffer;
    }

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

    bool _valid() {
        return (_flags & 0x03) == 0x03;
    }

    void _setup(KeyType type) {
        switch (type) {
            case KeyType::NO_KEY:
                _flags = 0x00;
                break;
            case KeyType::PRIVATE_KEY:
                _flags |= 0x01;
                break;
            case KeyType::PUBLIC_KEY:
                _flags |= 0x02;
                break;
        }
    }
};

} //namespace helloworld


#endif //HELLOWORLD_CURVE_25519_H
