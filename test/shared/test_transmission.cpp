#include <utility>

#include <iostream>
#include "catch.hpp"

#include "../../src/server/transmission_file_server.h"

using namespace helloworld;

struct Test : public Callable<void, const std::string&, std::stringstream&&> {
    std::string result;
    explicit Test(std::string expected) : result(std::move(expected)) {}

    void callback(const std::string& username, std::stringstream&& data) override {
        if (data.str() != result) {
            throw Error("test failed: " + data.str() + " != " + result);
        };
    }

};


TEST_CASE("Check the basic functionality") {
    std::stringstream data{"Some simple message"};
    Test test{"Some simple message"};

    FileManager sender{&test};
    std::string username = "alice";
    sender.send(username, data);
    sender.receive();

    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
}
