#include "catch.hpp"

#include <vector>

#include "../../src/shared/user_data.h"

using namespace helloworld;

#include <limits.h>
#include <stdint.h>

struct X : Serializable<X> {
    serialize::structure& serialize(
        serialize::structure& result) const override {
        result.push_back(0);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }
    static X deserialize(const std::vector<unsigned char>&, uint64_t& from) {
        ++from;
        return {};
    }
    static X deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
    friend bool operator==(const X&, const X&) { return true; }
};

template <typename T>
std::vector<T>& operator+=(std::vector<T>& one, const std::vector<T>& two) {
    std::copy(two.begin(), two.end(), std::back_inserter(one));
    return one;
}

struct Y : Serializable<Y> {
    std::string s;
    int i;
    std::vector<char> v;

    Y(std::string s = "", int i = 0, std::vector<char> v = {})
        : s(s), i(i), v(v) {}
    serialize::structure& serialize(
        serialize::structure& result) const override {
        serialize::serialize(s, result);
        serialize::serialize(i, result);
        serialize::serialize(v, result);
        return result;
    }
    serialize::structure serialize() const override {
        serialize::structure result;
        return serialize(result);
    }

    static Y deserialize(const std::vector<unsigned char>& data,
                         uint64_t& from) {
        Y res;
        res.s = serialize::deserialize<decltype(s)>(data, from);
        res.i = serialize::deserialize<decltype(i)>(data, from);
        res.v = serialize::deserialize<decltype(v)>(data, from);
        return res;
    }
    static Y deserialize(const serialize::structure& data) {
        uint64_t from = 0;
        return deserialize(data, from);
    }
    friend bool operator==(const Y& a, const Y& b) {
        return a.i == b.i && a.s == b.s &&
               std::equal(a.v.begin(), a.v.end(), b.v.begin(), b.v.end());
    }
};

template <typename T>
using equality = bool (*)(const T&, const T&);

template <typename T>
bool eq(const T& a, const T& b) {
    return a == b;
}

template <typename T>
bool vec_eq(const std::vector<T>& a, const std::vector<T>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

template <typename T, equality<T> eq = eq>
struct test {
    int testnum{0};
    void run(const T& in) {
        ++testnum;
        SECTION(typeid(in).name(), std::to_string(testnum)) {
            serialize::structure serialized;
            serialize::serialize(in, serialized);
            uint64_t from = 0;
            T deserialized = serialize::deserialize<T>(serialized, from);
            CHECK(from == serialized.size());
            CHECK(eq(in, deserialized));
        }
    }
};

TEST_CASE("numberic types") {
    SECTION("char") {
        test<char> testint;
        testint.run(0);
        testint.run(CHAR_MAX);
        testint.run(CHAR_MIN);
    }
    SECTION("ints") {
        test<int> testint;
        testint.run(0);
        testint.run(INT_MAX);
        testint.run(INT_MIN);
    }
    SECTION("int 64") {
        test<int64_t> testint;
        testint.run(0l);
        testint.run(INT64_MAX);
        testint.run(INT64_MIN);
    }
    SECTION("size_t") {
        test<size_t> testint;
        testint.run(0l);
        testint.run(SIZE_MAX);
    }
    SECTION("long") {
        test<long> testint;
        testint.run(0l);
        testint.run(LONG_MAX);
        testint.run(LONG_MIN);
    }
}

TEST_CASE("User defined types") {
    SECTION("very simple") {
        test<X> t;
        t.run({});
    }
    SECTION("more complex") {
        test<Y> t;

        Y t1{};
        Y t2{std::string("pizze"), 0, std::vector<char>{}};

        Y t3{std::string(
                 "Cheesecake jelly-o candy apple pie. Muffin soufflé sesame "
                 "snaps. Candy jelly beans jelly beans. Candy cake cupcake "
                 "apple pie halvah gummies sesame snaps gummi bears."
                 "Dessert liquorice lemon drops fruitcake jelly-o dessert "
                 "gummies. Cake bear claw muffin "),
             -100, std::vector<char>{1, 2, 3}};
        t.run(t1);
        t.run(t2);
        t.run(t3);
    }
}

TEST_CASE("vector of objects") {
    SECTION("strings") {
        test<std::vector<std::string>, vec_eq<std::string>> test;

        std::vector<std::string> t1{};
        std::vector<std::string> t2{"one"};
        std::vector<std::string> t3{"ahoj", "kamo", "ako", "sa", "mas"};

        test.run(t1);
        test.run(t2);
        test.run(t3);
    }
    SECTION("user defined") {
        test<std::vector<X>, vec_eq<X>> test;

        std::vector<X> t1{};
        std::vector<X> t2{{}};
        std::vector<X> t3{{}, {}, {}, {}, {}};

        test.run(t1);
        test.run(t2);
        test.run(t3);
    }
}

template <typename T, typename = typename T::value_type>
bool operator==(const T& a, const T& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

TEST_CASE("nested containers") {
    SECTION("simple") {
        using tested_type = std::vector<std::vector<char>>;
        test<tested_type> t;

        tested_type t0 = {};
        tested_type t1 = {{'a'}, {'a', 'b', 'c'}, {}};
        tested_type t2 = {{'a', 'b', 'c', 'd', 'e', 'f'}};

        t.run(t0);
        t.run(t1);
        t.run(t2);
    }
    SECTION("totaly insane") {
        using tested_type = std::vector<std::vector<std::vector<std::string>>>;
        test<tested_type> t;

        tested_type t0 = {};
        tested_type t1 = {{{"why"}}};
        tested_type t2 = {
            {{"why"}, {"would", "you"}}, {{"even", "do"}}, {{"this"}}};

        t.run(t0);
        t.run(t1);
        t.run(t2);
    }
}

TEST_CASE("invalid deserializations") {
    CHECK_THROWS(Y::deserialize({}));
    CHECK_THROWS(Y::deserialize({1, 2, 3, 4, 5}));

    auto serialized = Y().serialize();
    CHECK_NOTHROW(Y::deserialize(serialized));

    serialized.pop_back();
    CHECK_THROWS(Y::deserialize(serialized));
}
