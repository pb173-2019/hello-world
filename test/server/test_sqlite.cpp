#include "catch.hpp"

#include "../../src/server/sqlite_database.h"

using namespace helloworld;

zero::bytes_t strToVec(const std::string &data) {
    return zero::bytes_t(data.begin(), data.end());
}

TEST_CASE("SQLITE Database test") {
    ServerSQLite db{};

    UserData data{555, "Pepa", "", strToVec("My sercret key")};
    db.insert(data, false);

    UserData pepa = db.select("Pepa");
    CHECK(pepa.name == "Pepa");
    CHECK(pepa.publicKey == strToVec("My sercret key"));

    pepa = db.select("pepa");
    CHECK(pepa.name.empty());

    pepa = db.select(555);
    CHECK(pepa.name == "Pepa");

    const auto &res = db.selectLike(data);
    CHECK(res[0]->name == "Pepa");
    CHECK(res[0]->id == 555);
}

TEST_CASE("SQLITE Database test multiple data") {
    std::string realPublicKey{
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3uY6co6Yx0wmIDB7k8A\n"
        "yAfuH7yyjCCP4DcE+Fn4Cvffn+cdQXIpuvvhKvLqBgwjIpgCblHuenr81KlVbbKR\n"
        "LCYl6n9OIvk3psxa9WH7t+mZKhiIPA4MnRw2cY/YNZZpxTqNbmo2EQhNBVox//sQ\n"
        "HA/XmcEM7sxj7OZlR39lZemdIYoVdRXb6VybbZVpVMZ2fhQfI/PpEbt4bA58kHz5\n"
        "quO/RHClh1wHb/XmjHDubZFr9ctYQA8+a6b3OTgtRlfg+iFuiC89eLcMxVOrWT3X\n"
        "uFfq/LQxgh6Ak03gYOfstKorHydVCTySj2SvGKXdYsaYT6bqRYUtOoyD6Wz+d8NB\n"
        "7wIDAQAB\n"
        "-----END PUBLIC KEY-----"};

    ServerSQLite db{};

    UserData d1{245, "Penopa", "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{2, "karel", "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{55535, "sunshine98", "", strToVec("My sercret key")};
    // real public key
    UserData d4{34, "novere", "", strToVec(realPublicKey)};
    UserData d5{8752, "mybestnick", "", strToVec("My sercret key")};
    UserData d6{53, "user666", "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);
    db.insert(d4, false);
    db.insert(d5, false);
    db.insert(d6, false);

    SECTION("Select like") {
        UserData query1{0, "user", "", {}};
        const auto &res1 = db.selectLike(query1);
        CHECK(res1[0]->name == "user666");
        CHECK(res1[0]->id == 53);

        UserData query2{0, "no", "", {}};
        const auto &res2 = db.selectLike(query2);
        REQUIRE(res2.size() == 2);
        CHECK(res2[0]->name == "Penopa");
        CHECK(res2[0]->id == 245);
        CHECK(res2[1]->name == "novere");
        CHECK(res2[1]->id == 34);
        CHECK(res2[1]->publicKey == strToVec(realPublicKey));
    }

    SECTION("Select") {
        UserData res = db.select("user666");
        CHECK(res.name == "user666");
        CHECK(res.id == 53);

        res = db.select("no");
        CHECK(res.name.empty());
        CHECK(res.publicKey.empty());

        UserData query3{34, "no", "", {}};
        res = db.select(query3);
        CHECK(res.name == "novere");

        UserData query4{8752, "", "", {}};
        res = db.select(query4);
        CHECK(res.name == "mybestnick");
    }
}

TEST_CASE("SQLITE Database no data") {
    ServerSQLite db{};
    UserData query1{0, "user", "", {}};
    CHECK(db.selectLike(query1).empty());
    UserData query2{0, "", "", {}};
    CHECK(db.selectLike(query2).empty());

    CHECK(db.select("user").name.empty());
    CHECK(db.select("").name.empty());
}

TEST_CASE("SQLITE Database no matching query") {
    ServerSQLite db{};

    UserData d1{245, "Penopa", "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{2, "karel", "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{55535, "sunshine98", "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);

    UserData query1{0, "nowhere", "", {}};
    const auto &res1 = db.selectLike(query1);
    CHECK(res1.empty());
}

TEST_CASE("SQLITE Database delete users") {
    ServerSQLite db{};

    UserData d1{245, "Penopa", "", strToVec("asdfasdfasdfasdfafb")};
    UserData d2{2, "karel", "", strToVec("adfbadfbasdfsdfbadgdsfcxx")};
    UserData d3{55535, "sunshine98", "", strToVec("My sercret key")};
    db.insert(d1, false);
    db.insert(d2, false);
    db.insert(d3, false);

    UserData query1{0, "Penopa", "", {}};
    CHECK(db.remove(query1));
    UserData query2{55535, "nowhere", "", {}};
    CHECK(db.remove(query2));
    UserData query3{22, "kkarel", "", {}};
    CHECK(db.selectLike(d2)[0]->name == "karel");
}

TEST_CASE("SQLITE basic operations messages / bundles table simple") {
    ServerSQLite db{};

    std::string realPublicKey{
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3uY6co6Yx0wmIDB7k8A\n"
        "yAfuH7yyjCCP4DcE+Fn4Cvffn+cdQXIpuvvhKvLqBgwjIpgCblHuenr81KlVbbKR\n"
        "LCYl6n9OIvk3psxa9WH7t+mZKhiIPA4MnRw2cY/YNZZpxTqNbmo2EQhNBVox//sQ\n"
        "HA/XmcEM7sxj7OZlR39lZemdIYoVdRXb6VybbZVpVMZ2fhQfI/PpEbt4bA58kHz5\n"
        "quO/RHClh1wHb/XmjHDubZFr9ctYQA8+a6b3OTgtRlfg+iFuiC89eLcMxVOrWT3X\n"
        "uFfq/LQxgh6Ak03gYOfstKorHydVCTySj2SvGKXdYsaYT6bqRYUtOoyD6Wz+d8NB\n"
        "7wIDAQAB\n"
        "-----END PUBLIC KEY-----"};

    UserData source{34, "novere", "asdfasdfasdfasdfafb",
                    strToVec(realPublicKey)};

    SECTION("Table messages") {
        db.insertData(34, source.serialize());

        std::vector<unsigned char> resultData = db.selectData(34);

        UserData result = UserData::deserialize(resultData);
        CHECK(result.sessionKey == source.sessionKey);
        CHECK(result.name == source.name);
        CHECK(result.publicKey == source.publicKey);

        // was emptied
        resultData = db.selectData(34);
        CHECK(resultData.empty());
    }

    SECTION("Table bundles") {
        db.insertBundle(34, source.serialize());

        std::vector<unsigned char> resultData = db.selectBundle(34);
        UserData result = UserData::deserialize(resultData);
        CHECK(result.sessionKey == source.sessionKey);
        CHECK(result.name == source.name);
        CHECK(result.publicKey == source.publicKey);

        db.updateBundle(34, std::vector<unsigned char>{1, 2, 3});
        resultData = db.selectBundle(34);
        CHECK(resultData == std::vector<unsigned char>{1, 2, 3});

        db.removeBundle(34);
        resultData = db.selectBundle(34);
        CHECK(resultData.empty());
    }
}

TEST_CASE("SQLITE blob storage advanced") {
    UserData s1{34, "novere", "asdfasdfasdfasdfafb", {1, 2, 3, 4}};
    UserData s2{0, "", "", {}};
    UserData s3{
        34,
        "honza",
        "asdfasdfasdfasdfafb",
        {11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}};

    std::vector<unsigned char> empty{};

    ServerSQLite db{};

    SECTION("Table messages") {
        db.insertData(99, s1.serialize());
        db.insertData(99, s3.serialize());
        db.insertData(5, s2.serialize());
        db.insertData(3, empty);

        std::vector<unsigned char> resultData = db.selectData(0);
        CHECK(resultData.empty());

        resultData = db.selectData(99);
        std::string nameSelected;
        UserData res1 = UserData::deserialize(resultData);
        CHECK(res1.sessionKey == "asdfasdfasdfasdfafb");
        nameSelected = res1.name;

        resultData = db.selectData(3);
        CHECK(resultData.empty());

        resultData = db.selectData(99);
        UserData res2 = UserData::deserialize(resultData);
        CHECK(res2.id == 34);

        if (res2.name == "novere") {
            CHECK(res2.publicKey == zero::bytes_t{1, 2, 3, 4});
        } else {
            CHECK(res2.name == "honza");
            CHECK(res2.publicKey == zero::bytes_t{11, 11, 11, 11, 11, 11, 11,
                                                  11, 11, 11, 11, 11, 11, 11,
                                                  11, 11, 11});
        }

        resultData = db.selectData(5);
        UserData res3 = UserData::deserialize(resultData);
        CHECK(res3.name.empty());
        CHECK(res3.sessionKey.empty());
        CHECK(res3.publicKey.empty());

        resultData = db.selectData(99);
        CHECK(resultData.empty());
    }

    SECTION("Table bundles") {
        db.insertBundle(99, s1.serialize());
        // re-insert data (updates)
        db.insertBundle(99, s3.serialize());
        db.insertBundle(5, s2.serialize());
        db.insertBundle(3, empty);

        std::vector<unsigned char> resultData = db.selectBundle(0);
        CHECK(resultData.empty());

        resultData = db.selectBundle(5);
        UserData res1 = UserData::deserialize(resultData);
        CHECK(res1.name.empty());
        CHECK(res1.sessionKey.empty());
        CHECK(res1.publicKey.empty());

        resultData = db.selectBundle(99);    // doesn't delete
        resultData = db.selectBundle(99);
        UserData res2 = UserData::deserialize(resultData);
        CHECK(res2.publicKey == zero::bytes_t{11, 11, 11, 11, 11, 11, 11, 11,
                                              11, 11, 11, 11, 11, 11, 11, 11,
                                              11});
        CHECK(res2.sessionKey == "asdfasdfasdfasdfafb");
        CHECK(res2.id == 34);
        CHECK(res2.name == "honza");

        db.removeBundle(5);
        resultData = db.selectBundle(5);
        CHECK(resultData.empty());

        db.updateBundle(6, {1, 2, 3});
        resultData = db.selectBundle(6);
        CHECK(resultData.empty());

        db.updateBundle(99, {});
        resultData = db.selectBundle(99);
        CHECK(resultData.empty());
    }
}

TEST_CASE("SQLITE bundles re-insertion updates") {
    ServerSQLite db{};

    db.insertBundle(3, std::vector<unsigned char>{1, 2, 3});
    db.insertBundle(4, std::vector<unsigned char>{4, 2, 3});
    db.insertBundle(2, std::vector<unsigned char>{1, 2, 4});

    // insertion update
    db.insertBundle(2, std::vector<unsigned char>{5, 5, 5});

    CHECK(db.selectBundle(2) == std::vector<unsigned char>{5, 5, 5});
    CHECK(db.selectBundle(4) == std::vector<unsigned char>{4, 2, 3});
    CHECK(db.selectBundle(3) == std::vector<unsigned char>{1, 2, 3});

    // insertion update 2x
    db.insertBundle(2, std::vector<unsigned char>{1, 5});
    db.insertBundle(2, std::vector<unsigned char>{8, 8, 8, 8, 1});

    CHECK(db.selectBundle(4) == std::vector<unsigned char>{4, 2, 3});
    CHECK(db.selectBundle(3) == std::vector<unsigned char>{1, 2, 3});
    CHECK(db.selectBundle(2) == std::vector<unsigned char>{8, 8, 8, 8, 1});
}