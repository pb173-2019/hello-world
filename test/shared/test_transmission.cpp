#include <utility>

#include <iostream>
#include "catch.hpp"

#include "../../src/server/transmission_file_server.h"

using namespace helloworld;

struct Test : public Callable<void, bool, const std::string&, std::stringstream&&> {
    std::string result;
    explicit Test(std::string expected) : result(std::move(expected)) {}

    void callback(bool /*unused*/, const std::string& username, std::stringstream&& data) override {
        //todo commented functionality
//        if (data.str() != result) {
//            throw Error("test failed: " + data.str() + " != " + result);
//        };
    }

};


TEST_CASE("Check the basic functionality") {
    std::stringstream data{"Some simple message"};
    Test test{"Some simple message"};

    ServerFiles sender{&test};
    std::string username = "alice";
    sender.send(username, data);
    sender.receive();

    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
    CHECK_NOTHROW(sender.receive());
}
