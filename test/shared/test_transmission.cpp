#include <iostream>
#include "catch.hpp"

#include "../../src/shared/transmission_file.h"

using namespace helloworld;

std::stringstream data{"Some simple message"};
void callback(unsigned long /*unused */, std::stringstream&& result) {
    if (data.str() != result.str())
        throw std::runtime_error("Test failed.");
}


TEST_CASE("Check the data") {
    FileManager sender{callback};
    unsigned long cid = 2056;
    sender.send(cid, data);
    sender.receive(cid);

    CHECK_THROWS(sender.receive());
    CHECK_THROWS(sender.receive(265));
}