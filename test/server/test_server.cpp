#include <fstream>
#include "catch.hpp"

#include "../../src/server/requests.h"
#include "../../src/server/server.h"

using namespace helloworld;

Response registerAlice(int connectionId, Server &server,
                       const std::string &name = "alice") {
    std::ifstream input("pub.pem");
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());

    RegisterRequest registerRequest(name, publicKey);
    Request request{Request::Type::CREATE, registerRequest.serialize(), 1};

    return server.handleUserRequest(connectionId, request);
}

Response completeAlice(int connectionId, Server &server,
                       std::vector<unsigned char> secret,
                       const std::string &name = "alice") {
    CompleteRegistrationRequest crRequest(secret, name);
    Request request{Request::Type::CREATE_COMPLETE, crRequest.serialize(), 2};
    return server.handleUserRequest(connectionId, request);
}

TEST_CASE("Add new user") {
    Server server;
    server.dropDatabase();
    int connectionId = server.establishConnection();
    server.setSessionKey(connectionId, std::vector<unsigned char>(128, 0));

    SECTION("New user") {
        auto response = registerAlice(connectionId, server);
        CHECK(response.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Registration already started") {
            CHECK(registerAlice(connectionId, server).type ==
                  Response::Type::SERVER_ERROR);
        }

        SECTION("Challenge incorrectly solved") {
            CompleteRegistrationRequest crRequest(
                std::vector<unsigned char>(256, 10), "alice");
            Request request{Request::Type::CREATE_COMPLETE,
                            crRequest.serialize(), 2};
            auto response = server.handleUserRequest(1, request);
            CHECK(response.type == Response::Type::SERVER_ERROR);
        }

        SECTION("Challenge correctly solved") {
            CHECK(completeAlice(connectionId, server, response.payload).type ==
                  Response::Type::OK);
        }
    }
}

TEST_CASE("User authentication") {
    Server server;
    server.dropDatabase();
    int connectionId = server.establishConnection();
    server.setSessionKey(connectionId, std::vector<unsigned char>(256, 0));
    auto response = registerAlice(connectionId, server);
    completeAlice(connectionId, server, response.payload);

    SECTION("Existing user") {
        AuthenticateRequest authRequest("alice");
        Request request{Request::Type::LOGIN, authRequest.serialize(), 10};

        auto response = server.handleUserRequest(connectionId, request);
        CHECK(response.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Challenge solved") {
            CompleteAuthenticationRequest caRequest(response.payload, "alice");
            Request request{Request::Type::LOGIN_COMPLETE,
                            caRequest.serialize(), 2};
            auto response = server.handleUserRequest(1, request);
            CHECK(response.type == Response::Type::SERVER_ERROR);
        }

        SECTION("Challenge not solved") {
            CompleteAuthenticationRequest caRequest(
                std::vector<unsigned char>(128, 10), "alice");
            Request request{Request::Type::LOGIN_COMPLETE,
                            caRequest.serialize(), 2};
            auto response = server.handleUserRequest(1, request);
            CHECK(response.type == Response::Type::SERVER_ERROR);
        }
    }

    SECTION("Non-existing user") {
        AuthenticateRequest authRequest("bob");
        Request request{Request::Type::LOGIN, authRequest.serialize(), 10};

        auto response = server.handleUserRequest(connectionId, request);
        CHECK(response.type == Response::Type::SERVER_ERROR);
    }
}

TEST_CASE("Get list") {
    Server server;
    server.dropDatabase();
    int connectionId = server.establishConnection();
    server.setSessionKey(connectionId, std::vector<unsigned char>(128, 0));

    SECTION("Expected users in list") {
        SECTION("No users") { CHECK(server.getUsers().empty()); }

        SECTION("Alice") {
            auto response = registerAlice(connectionId, server);
            completeAlice(connectionId, server, response.payload);

            CHECK(server.getUsers() == std::vector<std::string>{"alice"});
        }

        SECTION("Lots of users") {
            for (int i = 0; i < 100; ++i) {
                std::string name = "alice-" + std::to_string(i);
                auto response = registerAlice(connectionId, server, name);
                completeAlice(connectionId, server, response.payload, name);
            }

            CHECK(server.getUsers().size() == 100);
        }
    }
}
