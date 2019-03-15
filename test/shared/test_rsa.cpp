#include <iostream>
#include "catch.hpp"

#include "../../src/shared/rsa_2048.h"

using namespace helloworld;

TEST_CASE("Rsa keygen") {
    RSAKeyGen keyGen;

    keyGen.savePublicKey("pub.pem");
    keyGen.savePrivateKey("priv.pem", "123");

    RSA2048 rsa;
    rsa.loadPublicKey("pub.pem");
    std::vector<unsigned char> data = rsa.encrypt("My best message");

//    RSA2048 rsa2;
//    rsa2.loadPrivateKey("priv.pem", nullptr);
//    std::string res = rsa2.decrypt(data);
//
//    CHECK(res == "My best message");
}