//
// Created by ivan on 13.3.19.
//

#include "catch.hpp"
#include <sstream>
#include <string>
#include "../../src/shared/hmac.h"
#include "../../src/shared/utils.h"

using namespace helloworld;

TEST_CASE("TEST VECTORS") {
    std::vector<unsigned char> key;
    std::string data;
    std::string output;

    // test vectors from rfc4231
    SECTION("TEST 1") {
        key = std::vector<unsigned char>(20, 0x0b);
        data = "Hi There";
        output = "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                 "2379f4e2ce4ec2787ad0b30545e17cde"
                 "daa833b7d6b8a702038b274eaea3f4e4"
                 "be9d914eeb61f1702e696c203a126854";
    }
    SECTION("TEST 2 : Test with a key shorter than the length of the HMAC output.") {
        std::string key_string = "Jefe";
        key = std::vector<unsigned char>(key_string.begin(), key_string.end());
        data = "what do ya want for nothing?";
        output = "164b7a7bfcf819e2e395fbe73b56e0a3"
                 "87bd64222e831fd610270cd7ea250554"
                 "9758bf75c05a994a6d034f65f8f0e6fd"
                 "caeab1a34d4a6b4b636e070a38bce737";
    }
    SECTION("TEST 3 : Test with a combined length of key and data that is larger than 64 bytes") {
        key = std::vector<unsigned char>(20, 0xaa);
        data = std::string(50, 0xdd);
        output = "fa73b0089d56a284efb0f0756c890be9"
                 "b1b5dbdd8ee81a3655f83e33b2279d39"
                 "bf3e848279a722c806b485a47e67c807"
                 "b946a337bee8942674278859e13292fb";
    }
    SECTION("TEST 4 : Test with a combined length of key and data that is larger than 64 bytes") {
        for (unsigned char i = 1; i < 26; i++)
            key.push_back(i);
        data = std::string(50, 0xcd);
        output = "b0ba465637458c6990e5a8c5f61d4af7"
                 "e576d97ff94b872de76f8050361ee3db"
                 "a91ca5c11aa25eb4d679275cc5788063"
                 "a5f19741120c4f2de2adebeb10a298dd";
    }
    SECTION("TEST 5 : with trucation") {
        key = std::vector<unsigned char>(20, 0x0c);
        data = "Test With Truncation";

        output = "415fad6271580a531d4179bc891d87a6";
    }
    SECTION("TEST 6 : Test with a key larger than 128 bytes") {
        key = std::vector<unsigned char>(131, 0xaa);
        data = "Test Using Larger Than Block-Size Key - Hash Key First";
        output = "80b24263c7c1a3ebb71493c1dd7be8b4"
                 "9b46d1f41b4aeec1121b013783f8f352"
                 "6b56d037e05f2598bd0fd2215d6a1e52"
                 "95e64f73f63f0aec8b915a985d786598";
    }
    SECTION("TEST 7 : Test with a key and data that is larger than 128 bytes") {
        key = std::vector<unsigned char>(131, 0xaa);
        data = "This is a test using a larger than block-size key and a larger than block-size data. "
               "The key needs to be hashed before being used by the HMAC algorithm.";
    }


    INFO("key: " + to_hex(key));
    INFO("data: " + data);

    HMAC test;
    test.setKey(key);
    std::vector<unsigned char> ss(data.begin(), data.end());
    auto result = test.generate(ss);
    std::string hexResult = to_hex(result.data(), result.size());

    INFO("result: " + hexResult);
    INFO("expected: " + output);
    // because some tests use truncated output
    CHECK(hexResult.rfind(output, 0) == 0);
}