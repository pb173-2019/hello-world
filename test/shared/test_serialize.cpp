#include "catch.hpp"

#include <vector>

#include "../../src/shared/user_data.h"

using namespace helloworld;

TEST_CASE("Serialization and deserialization simple class") {

    UserData data { 6513246, "Honza", "2b7e151628aed2a6abf7158809cf4f3c", std::vector<unsigned char>(59, 65) };

    std::vector<unsigned char> ser = data.serialize();

    UserData result = UserData::deserialize(ser);
    CHECK(data.id == result.id);
    CHECK(data.name == result.name);
    CHECK(data.sessionKey == result.sessionKey);
    CHECK(data.publicKey == result.publicKey);
}

struct Nested : public Serializable<Nested> {
    std::vector<std::string> container;

    std::vector<unsigned char> serialize() const override {
        std::vector<unsigned char> result;
        Serializable::addNestedContainer<std::vector<std::string>, std::string>(result, container);
        return result;
    }

    static Nested deserialize(const std::vector<unsigned char> &data) {
        Nested userData;
        Serializable::getNestedContainer<std::vector<std::string>, std::string>(data, 0, userData.container);
        return userData;
    }
};


TEST_CASE("Serialize nested containers") {

    Nested nested;
    nested.container.emplace_back("Msdkjfbh");
    nested.container.emplace_back("Another long data with so many cgaracters, yet the serialization does not fail us.");
    nested.container.emplace_back("");
    nested.container.emplace_back("alwietkvuhn\t\b alwkerha w kle\n\nurah w   "
                                  " lei ufhawlefukha lsemig \tuah welkshegu\r\r\n\r\nawekeuanlsdkgusd");

    std::vector<unsigned char> data = nested.serialize();

    Nested result = Nested::deserialize(data);

    CHECK(result.container[0] == "Msdkjfbh");
    CHECK(result.container[1] == "Another long data with so many cgaracters, yet the serialization does not fail us.");
    CHECK(result.container[2] == "");
    CHECK(result.container[3] == "alwietkvuhn\t\b alwkerha w kle\n\nurah w   "
                                 " lei ufhawlefukha lsemig \tuah welkshegu\r\r\n\r\nawekeuanlsdkgusd");
}



