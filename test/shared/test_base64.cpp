//#include "catch.hpp"
//
//#include "../../src/shared/utils.h"
//#include "../../src/shared/base_64.h"
//
//
//TEST_CASE("Base64 encode") {
//    using namespace helloworld;
//    //RFC doc
//    Base64 encoder;
//
//    CHECK(encoder.encode(from_string("")) == from_string(""));
//    CHECK(encoder.encode(from_string("f")) == from_string("Zg=="));
//    CHECK(encoder.encode(from_string("fo")) == from_string("Zm8="));
//    CHECK(encoder.encode(from_string("foo")) == from_string("Zm9v"));
//    CHECK(encoder.encode(from_string("foob")) == from_string("Zm9vYg=="));
//    CHECK(encoder.encode(from_string("fooba")) == from_string("Zm9vYmE="));
//    CHECK(encoder.encode(from_string("foobar")) == from_string("Zm9vYmFy"));
//}
//
//TEST_CASE("Base64 decode") {
//    using namespace helloworld;
//    Base64 encoder;
//
//    CHECK(encoder.decode(from_string("")) == from_string(""));
//    CHECK(encoder.decode(from_string("Zg==")) == from_string("f"));
//    CHECK(encoder.decode(from_string("Zm8=")) == from_string("fo"));
//    CHECK(encoder.decode(from_string("Zm9v")) == from_string("foo"));
//    CHECK(encoder.decode(from_string("Zm9vYg==")) == from_string("foob"));
//    CHECK(encoder.decode(from_string("Zm9vYmE=")) == from_string("fooba"));
//    CHECK(encoder.decode(from_string("Zm9vYmFy")) == from_string("foobar"));
//}
