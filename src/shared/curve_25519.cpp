#include "curve_25519.h"

namespace helloworld {

C25519KeyGen::C25519KeyGen() {
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


bool C25519KeyGen::savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) {
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

bool C25519KeyGen::savePrivateKeyPassword(const std::string &filename, const std::string &pwd) {
    return savePrivateKey(filename, getHexPwd(pwd), getHexIv(pwd));
}

bool C25519KeyGen::savePublicKey(const std::string &filename) const {
    std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
    if (!out_pub)
        return false;

    write_n(out_pub, _buffer_public, BIGINTSIZE);
    write_n(out_pub, _buffer_public, BIGINTSIZE);
    return true;
}

std::vector<unsigned char> C25519KeyGen::getPublicKey() const {
    return std::vector<unsigned char>(_buffer_public, _buffer_public + BIGINTSIZE * 2);
}


C25519::C25519() {
    mbedtls_ecdh_init(&_context);

    if (mbedtls_ecp_group_load(&_context.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        throw Error("Could not load CURVE25519 to context.");
    }
}


void C25519::setPeerPublicKey(const std::vector<unsigned char> &key) {
    if (key.size() != BIGINTSIZE) //works with X only
        throw Error("Invalid c25519 public key.");
    // Z-axis not user, init to 1
    if (mbedtls_mpi_lset(&_context.Qp.Z, 1) != 0) {
        throw Error("Failed to initialize peer's key.");
    }
    C25519KeyGen::mpiFromByteArray(&_context.Qp.X, key.data(), BIGINTSIZE);
    _setup(KeyType::PUBLIC_KEY);
}

void C25519::loadPeerPublicKey(const std::string &keyFile) {
    std::ifstream input{keyFile, std::ios::in | std::ios::binary};
    if (!input) return;

    std::vector<unsigned char> buffer(BIGINTSIZE);
    read_n(input, buffer.data(), BIGINTSIZE);
    setPeerPublicKey(buffer);
}

void C25519::setPublicKey(const std::vector<unsigned char> &key) {
    if (key.size() != BIGINTSIZE * 2) //X & Y axis
        throw Error("Invalid c25519 public key.");
    C25519KeyGen::mpiFromByteArray(&_context.Q.X, key.data(), BIGINTSIZE);
    C25519KeyGen::mpiFromByteArray(&_context.Q.Y, key.data() + BIGINTSIZE, BIGINTSIZE);
    //_setup(KeyType::PUBLIC_KEY);   only the peer's public key is needed
}

void C25519::loadPublicKey(const std::string &keyFile) {
    std::ifstream input{keyFile, std::ios::in | std::ios::binary};
    if (!input) return;

    std::vector<unsigned char> buffer(BIGINTSIZE *
    2);
    read_n(input, buffer.data(), BIGINTSIZE * 2);
    setPublicKey(buffer);
}

void C25519::loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) {
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

void C25519::loadPrivateKey(const std::string &keyFile, const std::string &pwd) {
    loadPrivateKey(keyFile, C25519KeyGen::getHexPwd(pwd), C25519KeyGen::getHexIv(pwd));
}


std::vector<unsigned char> C25519::getShared() {
    if (!_valid())
        throw Error("C25519 not initialized properly.");

    if (mbedtls_ecdh_compute_shared(&_context.grp, &_context.z, &_context.Qp, &_context.d,
                                    mbedtls_ctr_drbg_random, _random.getEngine()) != 0) {
        throw Error("Could not compute shared secret (ECDH).");
    }
    std::vector<unsigned char> buffer(BIGINTSIZE);
    C25519KeyGen::mpiToByteArray(&_context.z, buffer.data(), BIGINTSIZE);
    return buffer;
}


bool C25519::_valid() {
    return (_flags & 0x03) == 0x03;
}

void C25519::_setup(KeyType type) {
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

} //namespace helloworld
