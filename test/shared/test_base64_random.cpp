#include "catch.hpp"

#include "../../src/shared/utils.h"
#include "../../src/shared/base_64.h"
#include "../../src/shared/random.h"

using namespace helloworld;

TEST_CASE("Base64 encode") {
    //RFC doc
    Base64 encoder;

    CHECK(encoder.encode(from_string("")) == from_string(""));
    CHECK(encoder.encode(from_string("f")) == from_string("Zg=="));
    CHECK(encoder.encode(from_string("fo")) == from_string("Zm8="));
    CHECK(encoder.encode(from_string("foo")) == from_string("Zm9v"));
    CHECK(encoder.encode(from_string("foob")) == from_string("Zm9vYg=="));
    CHECK(encoder.encode(from_string("fooba")) == from_string("Zm9vYmE="));
    CHECK(encoder.encode(from_string("foobar")) == from_string("Zm9vYmFy"));
}

TEST_CASE("Base64 decode") {
    Base64 encoder;

    CHECK(encoder.decode(from_string("")) == from_string(""));
    CHECK(encoder.decode(from_string("Zg==")) == from_string("f"));
    CHECK(encoder.decode(from_string("Zm8=")) == from_string("fo"));
    CHECK(encoder.decode(from_string("Zm9v")) == from_string("foo"));
    CHECK(encoder.decode(from_string("Zm9vYg==")) == from_string("foob"));
    CHECK(encoder.decode(from_string("Zm9vYmE=")) == from_string("fooba"));
    CHECK(encoder.decode(from_string("Zm9vYmFy")) == from_string("foobar"));
}


TEST_CASE("Random generator") {
    using namespace helloworld;
    Random random{};

    size_t num = random.getBounded(565231, 6854635);
    CHECK(num >= 565231);
    CHECK(num < 6854635);

    num = random.getBounded(0, 2);
    CHECK(num >= 0);
    CHECK(num < 2);

    num = random.getBounded(5, 58);
    CHECK(num >= 5);
    CHECK(num < 58);
}


TEST_CASE("Salt generator - pseudo random") {
    using namespace helloworld;
    Salt salt1{"asdfjvdsbvkjsdcaskjncaksdjf"};
    Salt salt2{"asdfjvdsbvkjsdcaskjncaksdjf"};
    Salt salt3{"asdfjvdsbvkjsdcaskjncaksdjf"};
    Salt salt4{"asdfjvdsbvkjsdcaskjncaksdjf"};

    std::string s1 = salt1.get();
    std::string s2 = salt2.get();
    std::string s3 = salt3.get();
    std::string s4 = salt4.get();

    CHECK(s1 == s2);
    CHECK(s2 == s3);
    CHECK(s3 == s4);

    //too short seed
    CHECK_THROWS(Salt{""});
    CHECK_THROWS(Salt{"acbdjnruskchtk"});
}
