#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/shared/requests.h"
#include "../../src/server/server.h"

using namespace helloworld;

Response registerAlice(Server &server, const std::string &name) {
    std::string sessionKey = "2b7e151628aed2a6abf7158809cf4f3c";
    std::ifstream input("alice_pub.pem");
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());

    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());

    AuthenticateRequest registerRequest(name, key);
    //sets the transmission manager for server
    registerRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
    Request request{{Request::Type::CREATE, 1, 0}, registerRequest.serialize()};

    return server.handleUserRequest(request);
}

Response completeAlice(Server &server, const std::vector<unsigned char>& secret,
                       const std::string &name, Request::Type type) {
    RSA2048 rsa;
    rsa.loadPrivateKey("alice_priv.pem", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");

    CompleteAuthRequest crRequest(std::move(rsa.sign(secret)), name);
    Request request{{type, 2, 0}, crRequest.serialize()};
    return server.handleUserRequest(request);
}

TEST_CASE("Create key") {
    RSAKeyGen keygen;
    keygen.savePrivateKey("alice_priv.pem", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Add new user") {
    Server server;

    std::string name = "alice";

    SECTION("New user") {
        auto response = registerAlice(server, name);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Registration already started") {
            CHECK_THROWS(registerAlice(server, name));
        }

        SECTION("Challenge incorrectly solved") {
            CompleteAuthRequest crRequest(
                    std::vector<unsigned char>(256, 10), name);
            Request request{{Request::Type::CREATE_COMPLETE, 2, 0},
                            crRequest.serialize()};
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge correctly solved") {
            CHECK(completeAlice(server, response.payload, name, Request::Type::CREATE_COMPLETE).header.type ==
                  Response::Type::OK);
        }
    }
    server.dropDatabase();
}

TEST_CASE("User authentication") {
    Server server;
    std::string name = "alice";

    auto response = registerAlice(server, name);
    completeAlice(server, response.payload, name, Request::Type::CREATE_COMPLETE);
    //registration opened transmission
    server.closeTransmission(name);

    SECTION("Existing user") {
        AuthenticateRequest authRequest("alice", {});
        authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
        Request request{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};

        auto response = server.handleUserRequest(request);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Challenge not solved 1") {
            CompleteAuthRequest caRequest(response.payload, name);
            Request request{{Request::Type::LOGIN_COMPLETE, 2, 0},
                            caRequest.serialize()};
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge not solved 2") {
            CompleteAuthRequest caRequest(
                    std::vector<unsigned char>(128, 10), name);
            Request request{{Request::Type::LOGIN_COMPLETE, 2, 0},
                            caRequest.serialize()};
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge solved") {
            auto result = completeAlice(server, response.payload, name, Request::Type::LOGIN_COMPLETE);
            CHECK(result.header.type == Response::Type::OK);
        }
    }

    SECTION("Non-existing user") {
        AuthenticateRequest authRequest("bob", {});
        authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
        Request request{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};

        CHECK_THROWS(server.handleUserRequest(request));
    }
    server.dropDatabase();
}

TEST_CASE("Delete & logout") {
    Server server;
    std::string name = "alice";

    auto response = registerAlice(server, name);
    completeAlice(server, response.payload, name, Request::Type::CREATE_COMPLETE);

    GenericRequest nameId{0, name};
    Request logoutRequest{{Request::Type::LOGOUT, 0, 0}, nameId.serialize()};
    auto logoutReponse = server.handleUserRequest(logoutRequest);
    CHECK(logoutReponse.header.type == Response::Type::OK);

    //login
    AuthenticateRequest authRequest("alice", {});
    authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
    Request login{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};
    response = server.handleUserRequest(login);
    completeAlice(server, response.payload, name, Request::Type::LOGIN_COMPLETE);

    Request deleteUser{{Request::Type::REMOVE, 0, 0}, nameId.serialize()};
    auto removeReponse = server.handleUserRequest(logoutRequest);
    CHECK(removeReponse.header.type == Response::Type::OK);
    //try to log in
    response = server.handleUserRequest(login);
    CHECK(response.header.type != Response::Type::OK);
    server.dropDatabase();
}

TEST_CASE("Get list") {
    Server server;
    std::string name = "alice";

    SECTION("Expected users in list") {
        SECTION("No users") { CHECK(server.getUsers("").empty()); }

        SECTION("Alice") {
            auto response = registerAlice(server, name);
            completeAlice(server, response.payload, name, Request::Type::CREATE_COMPLETE);

            CHECK(server.getUsers("") == std::vector<std::string>{"alice"});
        }

        SECTION("Lots of users") {
            for (int i = 0; i < 100; ++i) {
                std::string name = "alice-" + std::to_string(i);
                auto response = registerAlice(server, name);
                completeAlice(server, response.payload, name, Request::Type::CREATE_COMPLETE);
            }

            CHECK(server.getUsers("").size() == 100);
        }
    }
    server.dropDatabase();
}
