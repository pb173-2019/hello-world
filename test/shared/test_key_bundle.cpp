//
// Created by ivan on 30.3.19.
//

#include <sstream>
#include <string>
#include "catch.hpp"

#include "../../src/shared/curve_25519.h"
#include "../../src/shared/random.h"
#include "../../src/shared/requests.h"

using namespace helloworld;

template struct helloworld::KeyBundle<C25519>;
TEST_CASE("serialization test") {
    Random r{};

    KeyBundle<C25519> keyBundle;

    keyBundle.identityKey = r.getKey(KeyBundle<C25519>::key_len);
    keyBundle.preKey = r.getKey(KeyBundle<C25519>::key_len);

    keyBundle.preKeySingiture = r.get(KeyBundle<C25519>::signiture_len);

    keyBundle.oneTimeKeys.push_back(r.getKey(KeyBundle<C25519>::key_len));
    keyBundle.generateTimeStamp();

    auto data = keyBundle.serialize();

    KeyBundle<C25519> newBundle =
        Serializable<KeyBundle<C25519> >::deserialize(data);
    CHECK(keyBundle.timestamp == newBundle.timestamp);
    CHECK(keyBundle.identityKey == newBundle.identityKey);
    CHECK(keyBundle.preKey == newBundle.preKey);
    CHECK(keyBundle.preKeySingiture == newBundle.preKeySingiture);
    CHECK(keyBundle.oneTimeKeys == newBundle.oneTimeKeys);
}

// this testing violates the access memory policy...

// TEST_CASE("key zeroize test - vector erased") {
//    unsigned char* ptr = nullptr;
//    {
//        KeyBundle<C25519> keyBundle;
//        keyBundle.identityKey = zero::bytes_t{1,2,3,4,5,6,7,8,9,10};
//        ptr = keyBundle.identityKey.data();
//        CHECK(ptr[0] == 1);
//        CHECK(ptr[3] == 4);
//    }
//    CHECK(ptr[0] == 0);
//    CHECK(ptr[3] == 0);
//}

// TEST_CASE("key zeroize test - vector moved") {
//    KeyBundle<C25519> keyBundle;
//    keyBundle.identityKey = zero::bytes_t{1,2,3,4};
//    unsigned char* ptr = keyBundle.identityKey.data();
//
//    CHECK(ptr[0] == 1);
//    CHECK(ptr[3] == 4);
//    zero::bytes_t moved = std::move(keyBundle.identityKey);
//    CHECK(keyBundle.identityKey.size() == 0);
//    CHECK(moved.data()[0] == 1);
//    CHECK(moved.data()[3] == 4);
//    CHECK(moved.data() != ptr);
//    CHECK(ptr[0] == 0);
//    CHECK(ptr[3] == 0);
//}