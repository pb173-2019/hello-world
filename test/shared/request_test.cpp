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
#include "../../src/shared/request.h"
#include "../../src/shared/utils.h"
#include "cstdlib"

using namespace helloworld;

TEST_CASE("generate Serialize request header and deserialize") {
    Request::Header header;

    SECTION("Simple test 1") {
        header.type = Request::Type::CREATE;
        header.userId = 0;
    }
    SECTION("Simple test 2") {
        header.type = Request::Type::SEND;
        header.userId = 5;
    }

    SECTION("Simple test 3") {
        header.type = Request::Type::LOGIN;
        header.userId = 55;
    }

    // just for testing purposes
    Request::Header oheader = Serializable<Request::Header>::deserialize(header.serialize());

    CHECK(header.type == oheader.type);
    CHECK(header.messageNumber == oheader.messageNumber);
    CHECK(header.userId == oheader.userId);

}

TEST_CASE("generate Serialize response header and deserialize") {
    Response::Header header;

    SECTION("Simple test 1") {
        header.type = Response::Type::OK;
        header.userId = 0;
    }
    SECTION("Simple test 2") {
        header.type = Response::Type::USER_AUTHENTICATED;
        header.userId = 5;
    }

    SECTION("Simple test 3") {
        header.type = Response::Type::INVALID_AUTH;
        header.userId = 55;
    }

    // just for testing purposes
    Response::Header oheader = Serializable<Response::Header>::deserialize(header.serialize());

    CHECK(header.type == oheader.type);
    CHECK(header.messageNumber == oheader.messageNumber);
    CHECK(header.userId == oheader.userId);


}