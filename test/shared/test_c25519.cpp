#include <iostream>
#include "catch.hpp"

#include "../../src/shared/curve_25519.h"

using namespace helloworld;

//std::vector<unsigned char> toBytes(const std::string &msg) {
//    return std::vector<unsigned char>(msg.begin(), msg.end());
//}

TEST_CASE("Curve keygen & key loading") {
    C25519KeyGen keyGen1;
    C25519KeyGen keyGen2;

    C25519 client;
    C25519 server;
    
    SECTION("No encryption") {
        keyGen1.savePublicKey("client.c25519");
        keyGen1.savePrivateKey("client-priv.c25519", "", "");
        client.loadPrivateKey("client-priv.c25519", "", "");

        keyGen2.savePublicKey("server.c25519");
        keyGen2.savePrivateKey("server-priv.c25519", "", "");
        client.loadPrivateKey("server-priv.c25519", "", "");
    }

    SECTION("With encryption") {
        keyGen1.savePublicKey("client.c25519");
        keyGen1.savePrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");
        client.loadPrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");

        keyGen2.savePublicKey("server.c25519");
        keyGen2.savePrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a", "2b7e151628aed2a6abf7158809cf4f3c");
        client.loadPrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a", "2b7e151628aed2a6abf7158809cf4f3c");
    }
    client.loadPeerPublicKey("server.c25519");
    server.loadPeerPublicKey("client.c25519");

    CHECK(client.getShared() == server.getShared());
}