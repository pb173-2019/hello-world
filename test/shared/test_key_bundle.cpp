//
// Created by ivan on 30.3.19.
//

#include "catch.hpp"
#include <sstream>
#include <string>

#include "../../src/shared/requests.h"
#include "../../src/shared/random.h"
#include "../../src/shared/curve_25519.h"

using namespace helloworld;

template struct helloworld::KeyBundle<C25519>;
TEST_CASE("serialization test")
{
    Random r{};

    KeyBundle<C25519> keyBundle;

    keyBundle.identityKey = r.get(KeyBundle<C25519>::key_len);
    keyBundle.preKey = r.get(KeyBundle<C25519>::key_len);

    keyBundle.preKeySingiture = r.get(KeyBundle<C25519>::signiture_len);

    keyBundle.oneTimeKeys.push_back(r.get(KeyBundle<C25519>::key_len));
    keyBundle.generateTimeStamp();

    auto data = keyBundle.serialize();

    KeyBundle<C25519> newBundle = Serializable<KeyBundle<C25519> >::deserialize(data);
    CHECK(keyBundle.timestamp == newBundle.timestamp);
    CHECK(keyBundle.identityKey == newBundle.identityKey);
    CHECK(keyBundle.preKey == newBundle.preKey);
    CHECK(keyBundle.preKeySingiture == newBundle.preKeySingiture);
    CHECK(keyBundle.oneTimeKeys == newBundle.oneTimeKeys);
}