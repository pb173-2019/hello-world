#include <iostream>
#include "catch.hpp"

#include "../../src/shared/curve_25519.h"
#include "../../include/eddsa/eddsa.h"


using namespace helloworld;

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
    client.loadPublicKey("server.c25519");
    server.loadPublicKey("client.c25519");

    CHECK(client.getShared() == server.getShared());
}


TEST_CASE("X25519 test vectors ") {

    std::vector<unsigned char> scalar = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    std::vector<unsigned char> u_coordinate = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    std::vector<unsigned char> result(32);
    x25519(result.data(), scalar.data(), u_coordinate.data());
    CHECK(result == from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

//    scalar = from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
//    u_coordinate = from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
//    x25519(result.data(), scalar.data(), u_coordinate.data());
//    CHECK(result == from_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
}

TEST_CASE("Curve signatures") {
    //key files generated ^^

    C25519 client;
    C25519 server;

    client.loadPrivateKey("client-priv.c25519", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");
    client.loadPublicKey("server.c25519");

    server.loadPrivateKey("server-priv.c25519", "323994cfb9da285a5d9642e1759b224a", "2b7e151628aed2a6abf7158809cf4f3c");
    server.loadPublicKey("client.c25519");

    std::vector<unsigned char> msg{1, 51, 21, 2, 12, 6, 6, 51, 65, 46, 84, 6, 51, 35, 6, 46, 51, 35, 46, 3, 35, 46, 4};
    std::vector<unsigned char> signature = client.sign(msg);
    CHECK(server.verify(signature, msg));
}