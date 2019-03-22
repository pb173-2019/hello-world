#include <iostream>
#include "catch.hpp"

#include "../../src/shared/transmission_file.h"

using namespace helloworld;

struct Test : public Callable<void, unsigned long, std::stringstream&&> {
    std::string result;
    explicit Test(const std::string& expected) : result(expected) {}

    void callback(unsigned long id, std::stringstream&& data) override {
        if (data.str() != result) {
            throw Error("test failed: " + data.str() + " != " + result);
        };
    }

};


TEST_CASE("Check the basic functionality") {
    std::stringstream data{"Some simple message"};
    Test test{"Some simple message"};

    FileManager sender{&test};
    unsigned long cid = 0;
    sender.send(cid, data);
    sender.receive();

    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
}
