//
// Created by ivan on 23.3.19.
//

#include "catch.hpp"
#include <sstream>
#include <string>
#include "../../src/shared/aes_gcm.h"
#include "../../src/shared/utils.h"
#include <iomanip>

using namespace helloworld;

TEST_CASE("Test vectors") {
    AESGCM aes{};
    aes.setPadding(Padding::NONE);
    std::stringstream plaintext;
    std::stringstream additionalData;

    std::string key;
    std::string iv;

    std::string tag;
    std::string cipher;

    SECTION("test vector 1") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        tag = "3247184B3C4F69A44DBCD22887BBB418";
        cipher = "";
    }

    SECTION("test vector 2") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        unsigned char bytes[64];
        from_hex("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2"
                 "E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B1"
                 "6AEDF5AA0DE657BA637B391AAFD255", bytes, 64);
        plaintext.write((char *) bytes, 64);

        tag = "4D5C2AF327CD64A62CF35ABD2BA6FAB4";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091473F5985";
    }
    SECTION("test vector 3") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        unsigned char bytes[64];
        from_hex("D9313225F88406E5A55909C5AFF5269A"
                 "86A7A9531534F7DA2E4C303D8A318A72"
                 "1C3C0C95956809532FCF0E2449A6B525"
                 "B16AEDF5AA0DE657BA637B391AAFD255", bytes, 64);
        plaintext.write((char *) bytes, 64);


        from_hex("3AD77BB40D7A3660A89ECAF32466EF97"
                 "F5D3D58503B9699DE785895A96FDBAAF"
                 "43B1CD7F598ECE23881B00E3ED030688"
                 "7B0C785E27E8AD3F8223207104725DD4", bytes, 64);
        additionalData.write((char *) bytes, 64);

        tag = "64C0232904AF398A5B67C10B53A5024D";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091473F5985";
    }
    SECTION("test vector 4") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        unsigned char bytes[64];
        from_hex("D9313225F88406E5A55909C5AFF5269A"
                 "86A7A9531534F7DA2E4C303D8A318A72"
                 "1C3C0C95956809532FCF0E2449A6B525"
                 "B16AEDF5AA0DE657BA637B39", bytes, 480 / 8);
        plaintext.write((char *) bytes, 480 / 8);


        from_hex("3AD77BB40D7A3660A89ECAF32466EF97"
                 "F5D3D585", bytes, 160 / 8);
        additionalData.write((char *) bytes, 160 / 8);

        tag = "F07C2528EEA2FCA1211F905E1B6A881B";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091";
    }

    CHECK(aes.setKey(key));
    CHECK(aes.setIv(iv));
    std::stringstream output;
    aes.encryptWithAd(plaintext, additionalData, output);
    CHECK(to_upper(to_hex(output.str().substr(0, 16))) == (tag));
    CHECK(to_upper(to_hex(output.str().substr(16, output.str().size()))) == (cipher));

    additionalData.clear();
    additionalData.seekg(std::ios::beg);

    std::stringstream decrypted;
    REQUIRE_NOTHROW(aes.decryptWithAd(output, additionalData, decrypted));
    CHECK(to_hex(plaintext.str()) == to_hex(decrypted.str()));
}

TEST_CASE("Test with vectors") {
    AESGCM aes{};
    aes.setPadding(Padding::NONE);
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> additionalData;

    std::string key;
    std::string iv;

    std::string tag;
    std::string cipher;

    SECTION("test vector 1") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        tag = "3247184B3C4F69A44DBCD22887BBB418";
        cipher = "";
    }

    SECTION("test vector 2") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";

        plaintext = from_hex("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2"
                 "E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B1"
                 "6AEDF5AA0DE657BA637B391AAFD255");

        tag = "4D5C2AF327CD64A62CF35ABD2BA6FAB4";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091473F5985";
    }
    SECTION("test vector 3") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";


        plaintext = from_hex("D9313225F88406E5A55909C5AFF5269A"
                 "86A7A9531534F7DA2E4C303D8A318A72"
                 "1C3C0C95956809532FCF0E2449A6B525"
                 "B16AEDF5AA0DE657BA637B391AAFD255");


        additionalData = from_hex("3AD77BB40D7A3660A89ECAF32466EF97"
                 "F5D3D58503B9699DE785895A96FDBAAF"
                 "43B1CD7F598ECE23881B00E3ED030688"
                 "7B0C785E27E8AD3F8223207104725DD4");

        tag = "64C0232904AF398A5B67C10B53A5024D";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091473F5985";
    }
    SECTION("test vector 4") {
        key = "FEFFE9928665731C6D6A8F9467308308";
        iv = "CAFEBABEFACEDBADDECAF888";


        plaintext = from_hex("D9313225F88406E5A55909C5AFF5269A"
                 "86A7A9531534F7DA2E4C303D8A318A72"
                 "1C3C0C95956809532FCF0E2449A6B525"
                 "B16AEDF5AA0DE657BA637B39");


        additionalData = from_hex("3AD77BB40D7A3660A89ECAF32466EF97"
                 "F5D3D585");

        tag = "F07C2528EEA2FCA1211F905E1B6A881B";
        cipher = "42831EC2217774244B7221B784D0D49C"
                 "E3AA212F2C02A4E035C17E2329ACA12E"
                 "21D514B25466931C7D8F6A5AAC84AA05"
                 "1BA30B396A0AAC973D58E091";
    }

    CHECK(aes.setKey(key));
    CHECK(aes.setIv(iv));
    std::vector<unsigned char> output;
    aes.encryptWithAd(plaintext, additionalData, output);

    std::string result = to_upper(to_hex(output));
    CHECK(result.substr(0, 32) == (tag));
    CHECK(result.substr(32, result.size()) == (cipher));

    std::vector<unsigned char> decrypted;
    REQUIRE_NOTHROW(aes.decryptWithAd(output, additionalData, decrypted));
    CHECK(to_hex(plaintext) == to_hex(decrypted));
}


