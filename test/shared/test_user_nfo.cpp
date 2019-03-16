#include "catch.hpp"

#include "../../src/shared/user_data.h"

using namespace helloworld;

TEST_CASE("Serialization and deserialization") {

    UserData data;
    data.id = 6513246;
    data.name = "Honza";
    data.publicKey = "--- BEGIN PUBLIC KEY ---\n"
                     "DJhgfvjadBVads65dG3adsaa\n"
                     "SV56D1ASD3VEB5GASD353dga\n"
                     "--- END PUBLIC KEY ---\n";

    std::vector<unsigned char> ser = data.serialize();

    UserData result = UserData::deserialize(ser);
    CHECK(data.id == result.id);
    CHECK(data.name == result.name);
    CHECK(data.publicKey == result.publicKey);
}
