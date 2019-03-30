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
        server.loadPrivateKey("server-priv.c25519", "", "");
    }

    SECTION("With encryption") {
        keyGen1.savePublicKey("client.c25519");
        keyGen1.savePrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c",
                               "323994cfb9da285a5d9642e1759b224a");
        client.loadPrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c",
                              "323994cfb9da285a5d9642e1759b224a");

        keyGen2.savePublicKey("server.c25519");
        keyGen2.savePrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a",
                               "2b7e151628aed2a6abf7158809cf4f3c");
        server.loadPrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a",
                              "2b7e151628aed2a6abf7158809cf4f3c");
    }
    client.loadPeerPublicKey("server.c25519");
    server.loadPeerPublicKey("client.c25519");

    CHECK(client.getShared() == server.getShared());
}

TEST_CASE("Curve signatures") {
    //key files generated ^^

    C25519 client;
    C25519 server;

    client.loadPrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");
    client.loadPeerPublicKey("server.c25519");

    server.loadPrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a", "2b7e151628aed2a6abf7158809cf4f3c");
    server.loadPeerPublicKey("client.c25519");

    std::vector<unsigned char> msg{1, 51, 21, 2, 12, 6, 6, 51, 65, 46, 84, 6, 51, 35, 6, 46, 51, 35, 46, 3, 35, 46, 4};
    std::vector<unsigned char> signature = client.sign(msg);
    CHECK(server.verify(signature, msg));
}