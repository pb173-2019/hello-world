#include <iostream>
#include "catch.hpp"

#include "../../src/shared/rsa_2048.h"
#include "../../src/shared/utils.h"

using namespace helloworld;

TEST_CASE("Rsa keygen & key loading") {
    RSAKeyGen keyGen;

    keyGen.savePublicKey("pub.pem");
    keyGen.savePrivateKey("priv.pem", "");

    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");
    std::vector<unsigned char> data = rsa.encrypt("My best message");

    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", "");
    std::string res = rsa2.decrypt(data);

    CHECK(res == "My best message");
}

TEST_CASE("Rsa encryption & decryption") {
    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");

    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", "");

    SECTION("Empty string") {
        std::vector<unsigned char> data = rsa.encrypt("");
        CHECK(rsa2.decrypt(data) == "");
    }

    SECTION("Normal string") {
        std::vector<unsigned char> data = rsa.encrypt("Normal string with some message in it.");
        CHECK(rsa2.decrypt(data) == "Normal string with some message in it.");
    }

    SECTION("AES key") {
        std::vector<unsigned char> rand = Random{}.get(16);
        std::string hex = to_hex(rand);
        std::vector<unsigned char> data = rsa.encrypt(hex);
        CHECK(rsa2.decrypt(data) == hex);
    }
}

TEST_CASE("Rsa sign & verify") {
    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");

    RSA2048 rsa2;
    rsa2.loadPrivateKey("priv.pem", "");

    std::vector<unsigned char> rand = Random{}.get(64);
    std::string hash = to_hex(rand);

    std::vector<unsigned char> data = rsa2.sign(hash);
    CHECK(rsa.verify(data, hash));
}

TEST_CASE("Invalid use") {
    RSA2048 pubkey;
    pubkey.loadPublicKey("pub.pem");

    RSA2048 privkey;
    privkey.loadPrivateKey("priv.pem", "");

    std::string str("Some random sentence.");
    std::vector<unsigned char> byte(256, 2);

    SECTION("Invalid length") {
        CHECK_THROWS(pubkey.encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        CHECK_THROWS(privkey.decrypt(std::vector<unsigned char>(258, 2)));
    }

    SECTION("Invalid operation on private key") {
        CHECK_THROWS(privkey.encrypt(str));
        CHECK_THROWS(privkey.verify(byte, str));
    }

    SECTION("Invalid operation on public key") {
        CHECK_THROWS(pubkey.sign(str));
        CHECK_THROWS(pubkey.decrypt(byte));
    }

    SECTION("Key mismatch") {
        RSAKeyGen keyGen;
        keyGen.savePublicKey("pub2.pem");
        keyGen.savePrivateKey("priv2.pem", "");

        RSA2048 other_pubkey;
        other_pubkey.loadPublicKey("pub2.pem");
        RSA2048 other_privkey;
        other_privkey.loadPrivateKey("priv2.pem", "");

        std::vector<unsigned char> data = other_pubkey.encrypt("Ahoj");
        CHECK_THROWS(privkey.decrypt(std::vector<unsigned char>(258, 2)));

        data = pubkey.encrypt("Ahoj");
        CHECK_THROWS(other_privkey.decrypt(std::vector<unsigned char>(258, 2)));
    }
}