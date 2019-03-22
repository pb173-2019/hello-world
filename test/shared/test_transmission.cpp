#include <iostream>
#include "catch.hpp"

#include "../../src/shared/transmission_file.h"

using namespace helloworld;

bool evaluated = false;

std::stringstream data{"Some simple message"};
void callback(unsigned long /*unused */, std::stringstream&& result) {
    if (data.str() != result.str())
        throw std::runtime_error("Test failed.");
    evaluated = true;
}


TEST_CASE("Check the basic functionality") {
    FileManager sender{callback};
    unsigned long cid = 0;
    sender.send(cid, data);
    sender.receive();

    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
    CHECK(evaluated);
}
