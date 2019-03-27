#include "catch.hpp"

#include "../../src/server/sqlite_database.h"

using namespace helloworld;

std::vector<unsigned char> strToVec(const std::string& data) {
    return std::vector<unsigned char>(data.begin(), data.end());
}


TEST_CASE("SQLITE Database test") {

    ServerSQLite db{};

    UserData data{ 555, "Pepa", "", strToVec("My sercret key")};
    db.insert(data, false);

    const auto& res = db.selectUsers(data);

    CHECK(res[0]->name == "Pepa");
    CHECK(res[0]->id == 555);
}

TEST_CASE("SQLITE Database test multiple data") {

    std::string realPublicKey {"-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3uY6co6Yx0wmIDB7k8A\n"
                               "yAfuH7yyjCCP4DcE+Fn4Cvffn+cdQXIpuvvhKvLqBgwjIpgCblHuenr81KlVbbKR\n"
                               "LCYl6n9OIvk3psxa9WH7t+mZKhiIPA4MnRw2cY/YNZZpxTqNbmo2EQhNBVox//sQ\n"
                               "HA/XmcEM7sxj7OZlR39lZemdIYoVdRXb6VybbZVpVMZ2fhQfI/PpEbt4bA58kHz5\n"
                               "quO/RHClh1wHb/XmjHDubZFr9ctYQA8+a6b3OTgtRlfg+iFuiC89eLcMxVOrWT3X\n"
                               "uFfq/LQxgh6Ak03gYOfstKorHydVCTySj2SvGKXdYsaYT6bqRYUtOoyD6Wz+d8NB\n"
                               "7wIDAQAB\n"
                               "-----END PUBLIC KEY-----"};

    ServerSQLite db{};

    UserData d1{ 245, "Penopa", "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{ 2, "karel", "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{ 55535, "sunshine98", "", strToVec("My sercret key")};
    //real public key
    UserData d4{ 34, "novere", "", strToVec(realPublicKey)};
    UserData d5{ 8752, "mybestnick", "", strToVec("My sercret key")};
    UserData d6{ 53, "user666", "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);
    db.insert(d4, false);
    db.insert(d5, false);
    db.insert(d6, false);

    UserData query1{0, "user", "", {}};
    const auto& res1 = db.selectUsersLike(query1);
    CHECK(res1[0]->name == "user666");
    CHECK(res1[0]->id == 53);

    UserData query2{0, "no", "", {}};
    const auto& res2 = db.selectUsersLike(query2);
    REQUIRE(res2.size() == 2);
    CHECK(res2[0]->name == "Penopa");
    CHECK(res2[0]->id == 245);
    CHECK(res2[1]->name == "novere");
    CHECK(res2[1]->id == 34);
    CHECK(res2[1]->publicKey == strToVec(realPublicKey));

    UserData query3{8752, "", "", {}};
    const auto& res3 = db.selectUsers(query3);
    CHECK(res3[0]->name == "mybestnick");
}

TEST_CASE("SQLITE Database no data") {
    ServerSQLite db{};
    UserData query1{0, "user", "", {}};
    CHECK(db.selectUsersLike(query1).empty());
    UserData query2{0, "", "", {}};
    CHECK(db.selectUsersLike(query2).empty());
}

TEST_CASE("SQLITE Database no matching query") {
    ServerSQLite db{};

    UserData d1{ 245, "Penopa",  "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{ 2, "karel",  "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{ 55535, "sunshine98",  "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);

    UserData query1{0, "nowhere", "", {}};
    const auto& res1 = db.selectUsers(query1);
    CHECK(res1.empty());
}

TEST_CASE("SQLITE Database delete") {
    ServerSQLite db{};

    UserData d1{ 245, "Penopa",  "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{ 2, "karel",  "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{ 55535, "sunshine98",  "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);

    UserData query1{0, "Penopa", "", {}};
    CHECK(db.removeUser(query1));
    UserData query2{55535, "nowhere", "", {}};
    CHECK(db.removeUser(query2));
    UserData query3{22, "kkarel", "", {}};
    CHECK(db.selectUsers(d2)[0]->name == "karel");
}
