#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/server/requests.h"
#include "../../src/server/server.h"

using namespace helloworld;

Response registerAlice(Server &server, const std::string &name) {
    std::string sessionKey = "2b7e151628aed2a6abf7158809cf4f3c";
    std::ifstream input("server_pub.pem");
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());

    //todo RSA make static method to load public key into vector
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());

    RegisterRequest registerRequest(name, sessionKey, key);
    Request request{{Request::Type::CREATE, 1, 0}, registerRequest.serialize()};

    return server.handleUserRequest(request);
}

Response completeAlice(Server &server, const std::vector<unsigned char>& secret,
                       const std::string &name) {
    RSA2048 rsa;
    rsa.loadPrivateKey("alice_priv.pem", "alice ma velke heslo");

    CompleteRegistrationRequest crRequest(std::move(rsa.decrypt(secret)), name);
    Request request{{Request::Type::CREATE_COMPLETE, 2, 0}, crRequest.serialize()};
    return server.handleUserRequest(request);
}

TEST_CASE("Create key") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "alice ma velke heslo");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Add new user") {
    Server server;
    server.dropDatabase();
    std::string name = "alice";

    SECTION("New user") {
        auto response = registerAlice(server, name);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Registration already started") {
            CHECK(registerAlice(server, name).header.type == Response::Type::GENERIC_SERVER_ERROR);
        }

        SECTION("Challenge incorrectly solved") {
            CompleteRegistrationRequest crRequest(
                    std::vector<unsigned char>(256, 10), name);
            Request request{{Request::Type::CREATE_COMPLETE, 2, 0},
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

    auto response = registerAlice(server, name);
    completeAlice(server, response.payload, name);

    SECTION("Existing user") {
        AuthenticateRequest authRequest("alice", "2b7e151628aed2a6abf7158809cf4f3c");
        Request request{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};

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
        AuthenticateRequest authRequest("bob", "2b7e151628aed2a6abf7158809cf4f3c");
        Request request{{Request::Type::LOGIN, 10, 0}, authRequest.serialize()};

        auto response = server.handleUserRequest(request);
        CHECK(response.header.type == Response::Type::GENERIC_SERVER_ERROR);
    }
}

TEST_CASE("Get list") {
    Server server;
    server.dropDatabase();
    std::string name = "alice";

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
