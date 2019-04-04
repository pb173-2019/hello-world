#include "catch.hpp"

#include "../../src/shared/double_ratchet.h"
#include "../../src/shared/curve_25519.h"

using namespace helloworld;

TEST_CASE("Double Ratchet one-way") {
    C25519KeyGen keygenAlice, keygenBob;

    std::vector<unsigned char> sharedKey(32, 'a');
    std::vector<unsigned char> ad(32, 'b');
    std::string message = "Hello Bob!";

    DoubleRatchet alice(sharedKey, keygenBob.getPublicKey());
    DoubleRatchet bob(sharedKey, keygenBob.getPublicKey(), keygenBob.getPrivateKey());

    auto encrypted = alice.RatchetEncrypt(from_string(message), ad);
    auto decrypted = bob.RatchetDecrypt(encrypted, ad);

    CHECK(to_string(decrypted) == message);
}
