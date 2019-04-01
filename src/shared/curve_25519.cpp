#include "curve_25519.h"

#include "eddsa/eddsa.h"

extern "C" {
#include "ed25519/keygen.h"
}

namespace helloworld {

C25519KeyGen::C25519KeyGen() {
    Random random{};

    _buffer_public.resize(KEY_BYTES_LEN);

    _buffer_private = random.get(KEY_BYTES_LEN);
    sc_clamp(_buffer_private.data());

    curve25519_keygen(_buffer_public.data(), _buffer_private.data());
}


bool C25519KeyGen::savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) {
    std::ofstream out_pri{filename, std::ios::out | std::ios::binary};
    if (!out_pri)
        return false;

    if (!key.empty()) {
        std::stringstream keystream{};
        AES128 cipher{};
        write_n(keystream, _buffer_private);
        cipher.setKey(key);
        cipher.setIv(iv);
        cipher.encrypt(keystream, out_pri);
    } else {
        write_n(out_pri, _buffer_private);
    }
    std::cout << to_hex(_buffer_private) << std::endl;
    std::cout << to_hex(_buffer_public) << std::endl << std::endl;

    return true;
}

bool C25519KeyGen::savePrivateKeyPassword(const std::string &filename, const std::string &pwd) {
    return savePrivateKey(filename, getHexPwd(pwd), getHexIv(pwd));
}

bool C25519KeyGen::savePublicKey(const std::string &filename) const {
    std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
    if (!out_pub)
        return false;

    write_n(out_pub, _buffer_public);
    return true;
}

std::vector<unsigned char> C25519KeyGen::getPublicKey() const {
    return _buffer_public;
}

C25519::C25519() = default;

void C25519::setPublicKey(const std::vector<unsigned char> &key) {
    if (key.size() != KEY_BYTES_LEN) //works with X only
        throw Error("Invalid c25519 public key.");
    _buffer_public = key;
    _setup(KeyType::PUBLIC_KEY);
}

void C25519::loadPublicKey(const std::string &keyFile) {
    std::ifstream input{keyFile, std::ios::in | std::ios::binary};
    if (!input) return;
    _buffer_public.resize(KEY_BYTES_LEN);
    read_n(input, _buffer_public.data(), KEY_BYTES_LEN);
    _setup(KeyType::PUBLIC_KEY);
}

void C25519::loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) {
    std::ifstream input{keyFile, std::ios::in | std::ios::binary};
    if (!input) return;

    _buffer_private.resize(KEY_BYTES_LEN);
    if (!key.empty()) {
        std::stringstream decrypted;
        AES128 cipher;
        cipher.setIv(iv);
        cipher.setKey(key);
        cipher.decrypt(input, decrypted);
        read_n(decrypted, _buffer_private.data(), _buffer_private.size());
    } else {
        read_n(input, _buffer_private.data(), _buffer_private.size());
    }
    _setup(KeyType::PRIVATE_KEY);
}

void C25519::loadPrivateKey(const std::string &keyFile, const std::string &pwd) {
    loadPrivateKey(keyFile, C25519KeyGen::getHexPwd(pwd), C25519KeyGen::getHexIv(pwd));
}

std::vector<unsigned char> C25519::getSharedStep1() {
    if (!_valid())
        throw Error("C25519 not initialized properly.");

    std::vector<unsigned char> u_coord = from_hex(
            "0900000000000000000000000000000000000000000000000000000000000000");
    std::vector<unsigned char> result(32);
    x25519(result.data(), _buffer_private.data(), u_coord.data());
    return result;
}

std::vector<unsigned char> C25519::getSharedStep2(const std::vector<unsigned char> &shared) {
    if (!_valid())
        throw Error("C25519 not initialized properly.");

    std::vector<unsigned char> result(32);
    x25519(result.data(), _buffer_private.data(), shared.data());

    return result;
}

std::vector<unsigned char> C25519::sign(const std::vector<unsigned char> &msg) {
    if ((_flags & 0x01) != 0x01)
        throw Error("Could not sign data: private key not set.");
    std::vector<unsigned char> output(XEDDSA_SIGN_LEN);

    std::vector<unsigned char> random = _random.get(XEDDSA_RAND_LEN);

    if (xed25519_sign(output.data(), _buffer_private.data(), msg.data(), msg.size(), random.data()) != 0) {
        throw Error("Failed to create signature.");
    }
    return output;
}

std::vector<unsigned char> C25519::sign(const std::string &msg) {
//todo message doesn't have to be in hex string (e.g. we assume the input is hex string)
    std::vector<unsigned char> data = from_hex(msg);
    return sign(data);
}

bool C25519::verify(const std::vector<unsigned char> &signature, const std::vector<unsigned char> &msg) {
    if ((_flags & 0x02) != 0x02)
        throw Error("Could not verify signature: public key not set.");
    if (signature.size() != XEDDSA_SIGN_LEN)
        throw Error("Invalid signature length.");

    return xed25519_verify(signature.data(), _buffer_public.data(), msg.data(), msg.size()) == 0;
}

bool C25519::verify(const std::vector<unsigned char> &signature, const std::string &msg) {
    std::vector<unsigned char> data = from_hex(msg);
    return verify(signature, data);
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
