#include "catch.hpp"

#include "../../src/server/file_database.h"

using namespace helloworld;

TEST_CASE("Database test") {

    FileDatabase db{ "test_db1.db" };

    UserData data{ 555, "Pepa", "My sercret key"};
    db.insert(data);

    const auto& res = db.select(data);

    CHECK(res[0]->name == "Pepa");
    CHECK(res[0]->id == 555);
}

TEST_CASE("Database test multiple data") {

    std::string realPublicKey {"-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3uY6co6Yx0wmIDB7k8A\n"
                               "yAfuH7yyjCCP4DcE+Fn4Cvffn+cdQXIpuvvhKvLqBgwjIpgCblHuenr81KlVbbKR\n"
                               "LCYl6n9OIvk3psxa9WH7t+mZKhiIPA4MnRw2cY/YNZZpxTqNbmo2EQhNBVox//sQ\n"
                               "HA/XmcEM7sxj7OZlR39lZemdIYoVdRXb6VybbZVpVMZ2fhQfI/PpEbt4bA58kHz5\n"
                               "quO/RHClh1wHb/XmjHDubZFr9ctYQA8+a6b3OTgtRlfg+iFuiC89eLcMxVOrWT3X\n"
                               "uFfq/LQxgh6Ak03gYOfstKorHydVCTySj2SvGKXdYsaYT6bqRYUtOoyD6Wz+d8NB\n"
                               "7wIDAQAB\n"
                               "-----END PUBLIC KEY-----"};

    FileDatabase db{ "test_db2.db" };

    UserData d1{ 245, "Penopa", "asdfasdfasdfasdfafb"};
    UserData d2{ 2, "karel", "adfbadfbasdfsdfbadgdsfcxx"};
    UserData d3{ 55535, "sunshine98", "My sercret key"};
    //real public key
    UserData d4{ 34, "novere", realPublicKey};
    UserData d5{ 8752, "mybestnick", "My sercret key"};
    UserData d6{ 53, "user666", "My sercret key"};
    db.insert(d1);
    db.insert(d2);
    db.insert(d3);
    db.insert(d4);
    db.insert(d5);
    db.insert(d6);

    UserData query1{0, "user", ""};
    const auto& res1 = db.select(query1);
    CHECK(res1[0]->name == "user666");
    CHECK(res1[0]->id == 53);

    UserData query2{0, "no", ""};
    const auto& res2 = db.select(query2);
    CHECK(res2[0]->name == "Penopa");
    CHECK(res2[0]->id == 245);
    CHECK(res2[1]->name == "novere");
    CHECK(res2[1]->id == 34);
    CHECK(res2[1]->publicKey == realPublicKey);

    UserData query3{8752, "", ""};
    const auto& res3 = db.select(query3);
    CHECK(res3[0]->name == "mybestnick");
}

TEST_CASE("Database no data") {
    FileDatabase db{ "test_db3.db" };
    UserData query1{0, "user", ""};
    CHECK_THROWS(db.select(query1));
}

TEST_CASE("Database no matching query") {
    FileDatabase db{ "test_db4.db" };

    UserData d1{ 245, "Penopa", "asdfasdfasdfasdfafb"};
    UserData d2{ 2, "karel", "adfbadfbasdfsdfbadgdsfcxx"};
    UserData d3{ 55535, "sunshine98", "My sercret key"};
    db.insert(d1);
    db.insert(d2);
    db.insert(d3);

    UserData query1{0, "nowhere", ""};
    const auto& res1 = db.select(query1);
    CHECK(res1.empty());
}
