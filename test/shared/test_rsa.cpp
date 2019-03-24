#include <iostream>
#include "catch.hpp"

#include "../../src/shared/rsa_2048.h"
#include "../../src/shared/utils.h"

using namespace helloworld;

std::vector<unsigned char> toBytes(const std::string &msg) {
    return std::vector<unsigned char>(msg.begin(), msg.end());
}

TEST_CASE("Rsa keygen & key loading") {
    std::string key{"2b7e151628aed2a6abf7158809cf4f3c"};
    std::string iv{"323994cfb9da285a5d9642e1759b224a"};
    RSAKeyGen keyGen;
    RSA2048 rsa;
    RSA2048 rsa2;
    std::vector<unsigned char> data;

    SECTION("No encryption") {
        keyGen.savePublicKey("pub.pem");
        keyGen.savePrivateKey("priv.pem", "", "");
        rsa.loadPublicKey("pub.pem");

        data = rsa.encrypt(toBytes("My best message"));
        rsa2.loadPrivateKey("priv.pem", "", "");
    }

    SECTION("With encryption") {
        keyGen.savePublicKey("pub.pem");
        keyGen.savePrivateKey("priv.pem", key, iv);
        rsa.loadPublicKey("pub.pem");
        data = rsa.encrypt(toBytes("My best message"));
        rsa2.loadPrivateKey("priv.pem", key, iv);
    }

    std::vector<unsigned char> res = rsa2.decrypt(data);
    CHECK(res == toBytes("My best message"));
}

TEST_CASE("Public key get & set") {
    std::string key{"323994cfb9da285a5d9642e1759b224a"};
    std::string iv{"2b7e151628aed2a6abf7158809cf4f3c"};
    RSAKeyGen keyGen;

    keyGen.savePrivateKey("priv.pem", key, iv);
    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", key, iv);

    std::vector<unsigned char> publicKey = keyGen.getPublicKey();
    RSA2048 rsa;
    rsa.setPublicKey(publicKey);

    std::vector<unsigned char> data = rsa.encrypt(toBytes("-"));
    CHECK(rsa2.decrypt(data) == toBytes("-"));
}

TEST_CASE("Rsa encryption & decryption") {
    //from now on in tests below, use these keys as the files generated remains
    std::string key{"323994cfb9da285a5d9642e1759b224a"};
    std::string iv{"2b7e151628aed2a6abf7158809cf4f3c"};

    RSAKeyGen keyGen;
    keyGen.savePublicKey("pub.pem");
    keyGen.savePrivateKey("priv.pem", key, iv);

    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");

    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", key, iv);

    SECTION("Empty string") {
        std::vector<unsigned char> data = rsa.encrypt(toBytes(""));
        CHECK(rsa2.decrypt(data) == toBytes(""));
    }

    SECTION("Normal string") {
        std::vector<unsigned char> data = rsa.encrypt(toBytes("Normal string with some message in it."));
        CHECK(rsa2.decrypt(data) == toBytes("Normal string with some message in it."));
    }

    SECTION("AES key") {
        std::vector<unsigned char> rand = Random{}.get(16);
        std::string hex = to_hex(rand);
        std::vector<unsigned char> data = rsa.encrypt(toBytes(hex));
        CHECK(rsa2.decrypt(data) == toBytes(hex));
    }
}

TEST_CASE("Rsa sign & verify") {
    std::string key{"323994cfb9da285a5d9642e1759b224a"};
    std::string iv{"2b7e151628aed2a6abf7158809cf4f3c"};

    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");

    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", key, iv);

    std::vector<unsigned char> rand = Random{}.get(64);
    std::string hash = to_hex(rand);

    std::vector<unsigned char> data = rsa2.sign(hash);
    CHECK(rsa.verify(data, hash));
}

TEST_CASE("Invalid use") {
    std::string key{"323994cfb9da285a5d9642e1759b224a"};
    std::string iv{"2b7e151628aed2a6abf7158809cf4f3c"};

    RSA2048 pubkey;
    pubkey.loadPublicKey("pub.pem");

    RSA2048 privkey;
    privkey.loadPrivateKey("priv.pem", key, iv);

    std::string str("Some random sentence.");
    std::vector<unsigned char> byte(256, 2);

    SECTION("Invalid length") {
        CHECK_THROWS(pubkey.encrypt(toBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
        CHECK_THROWS(privkey.decrypt(std::vector<unsigned char>(258, 2)));
    }

    SECTION("Invalid operation on private key") {
        CHECK_THROWS(privkey.encrypt(toBytes(str)));
        CHECK_THROWS(privkey.verify(byte, str));
    }

    SECTION("Invalid operation on public key") {
        CHECK_THROWS(pubkey.sign(str));
        CHECK_THROWS(pubkey.decrypt(byte));
    }

    SECTION("Key mismatch") {
        RSAKeyGen keyGen;
        keyGen.savePublicKey("pub2.pem");
        keyGen.savePrivateKey("priv2.pem", "", "");

        RSA2048 other_pubkey;
        other_pubkey.loadPublicKey("pub2.pem");
        RSA2048 other_privkey;
        other_privkey.loadPrivateKey("priv2.pem", "", "");

        std::vector<unsigned char> data = other_pubkey.encrypt(toBytes("Ahoj"));
        CHECK_THROWS(privkey.decrypt(std::vector<unsigned char>(258, 2)));

        data = pubkey.encrypt(toBytes("Ahoj"));
        CHECK_THROWS(other_privkey.decrypt(std::vector<unsigned char>(258, 2)));
    }
}