#include <vector>
#include "catch.hpp"

#include "../../src/shared/utils.h"

using namespace helloworld;

TEST_CASE("split") {
    std::vector<int> foo{1, 2, 3, 4, 5, 6};
    auto bar = split(foo);

    CHECK(bar.first == std::vector<int>{1, 2, 3});
    CHECK(bar.second == std::vector<int>{4, 5, 6});

    std::vector<int> x{1, 2, 3, 4, 5};
    auto a = split(x, 2);
    auto b = split(a.second, 2);
    CHECK(a.first == std::vector<int>{1, 2});
    CHECK(b.first == std::vector<int>{3, 4});
    CHECK(b.second == std::vector<int>{5});
}

