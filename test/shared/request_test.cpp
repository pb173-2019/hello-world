/**
 * @file request_test.cpp
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief simple tests for request and responses
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */


#include "catch.hpp"
#include <sstream>
#include <string>
#include "../../src/shared/rrmanip.h"
#include "../../src/shared/utils.h"
#include "cstdlib"

using namespace helloworld;

TEST_CASE("generate raw Request and then back") {
    Request irequest;

    SECTION("Empty payload") {
        irequest.type = Request::Type::CREATE;
    }
    SECTION("Small payload") {
        irequest.type = Request::Type::CREATE;
        std::string s = "short message";
        irequest.payload.resize(s.size());
        std::copy(s.begin(), s.end(), irequest.payload.data());
    }

    SECTION("Large payload") {
        irequest.type = Request::Type::CREATE;
        std::string s(100000, 'a');
        irequest.payload.resize(s.size());
        std::copy(s.begin(), s.end(), irequest.payload.data());
    }

    // just for testing purposes
    RequestBuilder builder(rand()); //NOLINT
    std::stringstream ss;
    builder.writeTo(irequest, ss);
    RequestParser parser;
    Request orequest = parser.parseRequest(ss);

    CHECK(irequest.type == orequest.type);
    CHECK(irequest.messageNumber == orequest.messageNumber);
    CHECK(irequest.payload == orequest.payload);


}

TEST_CASE("generate raw Response and then back") {
    Response irequest;

    SECTION("Empty payload") {
        irequest.type = Response::Type::OK;
    }
    SECTION("Small payload") {
        irequest.type = Response::Type::OK;
        std::string s = "short message";
        irequest.payload.resize(s.size());
        std::copy(s.begin(), s.end(), irequest.payload.data());
    }

    SECTION("Large payload") {
        irequest.type = Response::Type::OK;
        std::string s(100000, 'a');
        irequest.payload.resize(s.size());
        std::copy(s.begin(), s.end(), irequest.payload.data());
    }

    ResponseBuilder builder;
    std::stringstream ss;
    builder.writeTo(irequest, ss);
    ResponseParser parser;
    Response orequest = parser.parseResponse(ss);

    CHECK(irequest.type == orequest.type);
    CHECK(irequest.messageNumber == orequest.messageNumber);
    CHECK(irequest.payload == orequest.payload);


}

