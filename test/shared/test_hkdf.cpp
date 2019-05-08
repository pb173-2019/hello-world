//
// Created by ivan on 30.3.19.
//

#include <sstream>
#include <string>
#include "catch.hpp"

#include "../../src/shared/hkdf.h"
#include "../../src/shared/hmac_base.h"
#include "../../src/shared/utils.h"

using namespace helloworld;

TEST_CASE("test vectors RFC5869") {
    std::vector<unsigned char> info;
    zero::bytes_t salt;
    zero::bytes_t IKM;
    std::unique_ptr<hmac> hmacFunction;
    zero::str_t result;
    size_t len = 0;

    SECTION("SECTION 1") {
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA256, 32> >();
        IKM = zero::bytes_t(22, 0xb);
        for (size_t i = 0; i < 10; i++) info.push_back(0xf0 + i);
        for (size_t i = 0; i < 13; i++) salt.push_back(i);
        len = 42;
        result =
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865";
    }
    SECTION("SECTION 2") {
        for (unsigned i = 0; i < 80; i++) {
            info.push_back(static_cast<unsigned char>(0xb0 + i));
            salt.push_back(static_cast<unsigned char>(0x60 + i));
            IKM.push_back(static_cast<unsigned char>(i));
        }
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA256, 32> >();
        result =
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87";
        len = 82;
    }
    SECTION("SECTION 3") {
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA256, 32> >();
        IKM = zero::bytes_t(22, 0x0b);
        len = 42;
        result =
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8";
    }
    SECTION("SECTION 4") {
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA1, 20> >();
        IKM = zero::bytes_t(11, 0x0b);
        for (size_t i = 0; i < 10; i++) info.push_back(0xf0 + i);
        for (size_t i = 0; i < 13; i++) salt.push_back(i);
        len = 42;
        result =
            "085a01ea1b10f36933068b56efa5ad81"
            "a4f14b822f5b091568a9cdd4f155fda2"
            "c22e422478d305f3f896";
    }
    SECTION("SECTION 5") {
        for (unsigned i = 0; i < 80; i++) {
            info.push_back(static_cast<unsigned char>(0xb0 + i));
            salt.push_back(static_cast<unsigned char>(0x60 + i));
            IKM.push_back(static_cast<unsigned char>(i));
        }
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA1, 20> >();
        result =
            "0bd770a74d1160f7c9f12cd5912a06eb"
            "ff6adcae899d92191fe4305673ba2ffe"
            "8fa3f1a4e5ad79f3f334b3b202b2173c"
            "486ea37ce3d397ed034c7f9dfeb15c5e"
            "927336d0441f4c4300e2cff0d0900b52"
            "d3b4";
        len = 82;
    }
    SECTION("SECTION 6") {
        hmacFunction = std::make_unique<hmac_base<MBEDTLS_MD_SHA1, 20> >();
        IKM = zero::bytes_t(22, 0x0b);
        len = 42;
        result =
            "0ac1af7002b3d761d1e55298da9d0506"
            "b9ae52057220a306e07b6b87e8df21d0"
            "ea00033de03984d34918";
    }

    zero::str_t infoString;
    std::copy(info.begin(), info.end(), std::back_inserter(infoString));

    hkdf test(std::move(hmacFunction), infoString);
    test.setSalt(to_hex(salt));
    CHECK((test.generate(to_hex(IKM), len)) == result);
}

TEST_CASE("Default salt value test (RFC5869)") {
    hkdf test(std::make_unique<hmac_base<MBEDTLS_MD_SHA1, 20> >(), "");
    zero::bytes_t IKM(22, 0x0c);
    CHECK(test.generate(to_hex(IKM), 42) == ("2c91117204d745f3500d636a62f64f0a"
                                             "b3bae548aa53d423b0d1f27ebba6f5e5"
                                             "673a081d70cce7acfc48"));
}