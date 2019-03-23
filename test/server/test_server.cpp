#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/server/requests.h"
#include "../../src/server/server.h"

using namespace helloworld;

Response registerAlice(Server &server, const std::string &name) {
    std::ifstream input("pub.pem");
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());

    RegisterRequest registerRequest(name, publicKey);
    Request request{{Request::Type::CREATE, 1, 0} , registerRequest.serialize()};

    return server.handleUserRequest(request);
}

Response completeAlice(Server &server, std::vector<unsigned char> secret,
                       const std::string &name) {
    CompleteRegistrationRequest crRequest(std::move(secret), name);
    Request request{{Request::Type::CREATE_COMPLETE, 2, 0}, crRequest.serialize()};
    return server.handleUserRequest(request);
}

TEST_CASE("Add new user") {
    Server server;
    server.dropDatabase();
    std::string name = "alice";

    server.setSessionKey(name, std::vector<unsigned char>(128, 0));

    SECTION("New user") {
        auto response = registerAlice(server, name);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Registration already started") {
            CHECK(registerAlice(server, name).header.type == Response::Type::GENERIC_SERVER_ERROR);
        }

        SECTION("Challenge incorrectly solved") {
            CompleteRegistrationRequest crRequest(
                std::vector<unsigned char>(256, 10), name);
            Request request{{Request::Type::CREATE_COMPLETE,2, 0},
                            crRequest.serialize()};
            response = server.handleUserRequest(request);
            CHECK(response.header.type == Response::Type::GENERIC_SERVER_ERROR);
        }

        SECTION("Challenge correctly solved") {
            CHECK(completeAlice(server, response.payload, name).header.type ==
                  Response::Type::OK);
        }
    }
}

TEST_CASE("User authentication") {
    Server server;
    server.dropDatabase();
    std::string name = "alice";

    server.setSessionKey(name, std::vector<unsigned char>(256, 0));
    auto response = registerAlice(server, name);
    completeAlice(server, response.payload, name);

    SECTION("Existing user") {
        AuthenticateRequest authRequest("alice");
        Request request{{Request::Type::LOGIN,10, 0} , authRequest.serialize()};

        auto response = server.handleUserRequest(request);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Challenge solved") {
            CompleteAuthenticationRequest caRequest(response.payload, name);
            Request request{{Request::Type::LOGIN_COMPLETE, 2, 0},
                            caRequest.serialize()};
            response = server.handleUserRequest(request);
            CHECK(response.header.type == Response::Type::GENERIC_SERVER_ERROR);
        }

        SECTION("Challenge not solved") {
            CompleteAuthenticationRequest caRequest(
                std::vector<unsigned char>(128, 10), name);
            Request request{{Request::Type::LOGIN_COMPLETE, 2, 0},
                            caRequest.serialize()};
            response = server.handleUserRequest(request);
            CHECK(response.header.type == Response::Type::GENERIC_SERVER_ERROR);
        }
    }

    SECTION("Non-existing user") {
        AuthenticateRequest authRequest("bob");
        Request request{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};

        auto response = server.handleUserRequest(request);
        CHECK(response.header.type == Response::Type::GENERIC_SERVER_ERROR);
    }
}

TEST_CASE("Get list") {
    Server server;
    server.dropDatabase();
    std::string name = "alice";

    server.setSessionKey(name, std::vector<unsigned char>(128, 0));

    SECTION("Expected users in list") {
        SECTION("No users") { CHECK(server.getUsers().empty()); }

        SECTION("Alice") {
            auto response = registerAlice(server, name);
            completeAlice(server, response.payload, name);

            CHECK(server.getUsers() == std::vector<std::string>{"alice"});
        }

        SECTION("Lots of users") {
            for (int i = 0; i < 100; ++i) {
                std::string name = "alice-" + std::to_string(i);
                auto response = registerAlice(server, name);
                completeAlice(server, response.payload, name);
            }

            CHECK(server.getUsers().size() == 100);
        }
    }
}
