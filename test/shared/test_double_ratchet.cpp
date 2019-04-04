#include "catch.hpp"

#include "../../src/shared/curve_25519.h"
#include "../../src/shared/double_ratchet.h"

using namespace helloworld;

struct DR {
    DoubleRatchet alice;
    DoubleRatchet bob;
};

DR setup() {
    C25519KeyGen keygenAlice, keygenBob;
    std::vector<unsigned char> sharedKey(32, 'a');

    DoubleRatchet alice(sharedKey, keygenBob.getPublicKey());
    DoubleRatchet bob(sharedKey, keygenBob.getPublicKey(),
                      keygenBob.getPrivateKey());

    return DR{std::move(alice), std::move(bob)};
}

std::string getMessage(size_t count) {
    return "Hello " + std::to_string(count);
}

TEST_CASE("Double Ratchet one-way") {
    std::vector<unsigned char> ad(32, 'b');
    std::string message = "Hello Bob!";
    auto dr = setup();

    auto encrypted = dr.alice.RatchetEncrypt(from_string(message), ad);
    auto decrypted = dr.bob.RatchetDecrypt(encrypted, ad);

    CHECK(to_string(decrypted) == message);
}

TEST_CASE("Double Ratchet ping-pong") {
    std::vector<unsigned char> sharedKey(32, '1');
    std::vector<unsigned char> ad(32, '2');
    std::string message = "Hello!";
    auto dr = setup();

    auto encrypted = dr.alice.RatchetEncrypt(from_string(message), ad);
    auto decrypted = dr.bob.RatchetDecrypt(encrypted, ad);

    Message msg;
    for (int i = 0; i < 100; ++i) {
        auto plaintext = getMessage(i);
        if (i % 2 == 0) {
            msg = dr.alice.RatchetEncrypt(from_string(plaintext), ad);

            auto decrypted = to_string(dr.bob.RatchetDecrypt(msg, ad));
            CHECK(decrypted == plaintext);
        } else {
            msg = dr.bob.RatchetEncrypt(from_string(plaintext), ad);

            auto decrypted = to_string(dr.alice.RatchetDecrypt(msg, ad));
            CHECK(decrypted == plaintext);
        }
    }
}

TEST_CASE("Double Ratchet out-of-order") {
    std::vector<unsigned char> sharedKey(32, '1');
    std::vector<unsigned char> ad(32, '2');
    auto dr = setup();

    auto a1 = dr.alice.RatchetEncrypt(from_string("Hello, Bob!"), ad);
    CHECK(to_string(dr.bob.RatchetDecrypt(a1, ad)) == "Hello, Bob!");

    auto b1 = dr.bob.RatchetEncrypt(from_string("Greetings Alice."), ad);
    CHECK(to_string(dr.alice.RatchetDecrypt(b1, ad)) == "Greetings Alice.");

    auto a2 = dr.alice.RatchetEncrypt(from_string("Nice to meet you!"), ad);
    CHECK(to_string(dr.bob.RatchetDecrypt(a2, ad)) == "Nice to meet you!");

    auto b2 = dr.bob.RatchetEncrypt(from_string("Nice to meet you too."), ad);
    // SKIPPED

    auto a3 = dr.alice.RatchetEncrypt(from_string("hey"), ad);
    CHECK(to_string(dr.bob.RatchetDecrypt(a3, ad)) == "hey");

    auto a4 = dr.alice.RatchetEncrypt(from_string("hey 2"), ad);
    CHECK(to_string(dr.bob.RatchetDecrypt(a4, ad)) == "hey 2");

    auto b3 = dr.bob.RatchetEncrypt(from_string("hello"), ad);
    // SKIPPED

    auto b4 = dr.bob.RatchetEncrypt(from_string("bonjour"), ad);
    CHECK(b4.header.pn == 1);
    CHECK(b4.header.n == 2);
    CHECK(to_string(dr.alice.RatchetDecrypt(b4, ad)) == "bonjour");

    auto a5 = dr.alice.RatchetEncrypt(from_string("hey 3"), ad);
    CHECK(to_string(dr.bob.RatchetDecrypt(a5, ad)) == "hey 3");

    CHECK(to_string(dr.alice.RatchetDecrypt(b3, ad)) == "hello");
}
