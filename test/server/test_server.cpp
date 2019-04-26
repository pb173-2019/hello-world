#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/requests.h"
#include "../../src/server/server.h"
#include "../../src/shared/curve_25519.h"

using namespace helloworld;


Response registerAlice(Server &server, const std::string &name, MessageNumberGenerator& counter) {
    std::string sessionKey = "2b7e151628aed2a6abf7158809cf4f3c";
    std::ifstream input("alice_pub.pem");
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());

    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());

    AuthenticateRequest registerRequest(name, key);
    //sets the transmission manager for server
    registerRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
    Request request{{Request::Type::CREATE, 0}, registerRequest.serialize()};
    counter.setNumber(request);
    return server.handleUserRequest(request);
}

Response completeAlice(Server &server, const std::vector<unsigned char>& secret,
                       const std::string &name, Request::Type type,  MessageNumberGenerator& counter) {
    RSA2048 rsa;
    rsa.loadPrivateKey("alice_priv.pem", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");

    CompleteAuthRequest crRequest(std::move(rsa.sign(secret)), name);
    Request request{{type, 0}, crRequest.serialize()};

    counter.setNumber(request);
    return server.handleUserRequest(request);
}

TEST_CASE("Create key") {
    RSAKeyGen keygen;
    keygen.savePrivateKey("alice_priv.pem", "2b7e151628aed2a6abf7158809cf4f3c", "323994cfb9da285a5d9642e1759b224a");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Add new user") {
    MessageNumberGenerator aliceCounter;
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    std::string name = "alice";

    SECTION("New user") {
        auto response = registerAlice(server, name, aliceCounter);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Registration already started") {
            CHECK_THROWS(registerAlice(server, name, aliceCounter));
        }

        SECTION("Challenge incorrectly solved") {
            CompleteAuthRequest crRequest(
                    std::vector<unsigned char>(256, 10), name);
            Request request{{Request::Type::CHALLENGE, 0},
                            crRequest.serialize()};
            aliceCounter.setNumber(request);
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge correctly solved") {
            CHECK(completeAlice(server, response.payload, name, Request::Type::CHALLENGE, aliceCounter).header.type ==
                  Response::Type::USER_REGISTERED);
        }
        
        SECTION("Keys initialization") {
            Request request{{Request::Type::KEY_BUNDLE_UPDATE, 0}, {}};
        }
    }
    server.dropDatabase();
}

TEST_CASE("User authentication") {
    Server::test();
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    MessageNumberGenerator aliceCounter;
    std::string name = "alice";

    auto response = registerAlice(server, name, aliceCounter);
    completeAlice(server, response.payload, name, Request::Type::CHALLENGE, aliceCounter);
    //registration opened transmission
    server.logout(name);

    SECTION("Existing user") {
        AuthenticateRequest authRequest("alice", {});
        authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
        Request request{{Request::Type::LOGIN, 0}, authRequest.serialize()};
        aliceCounter.setNumber(request);

        auto response = server.handleUserRequest(request);
        CHECK(response.header.type == Response::Type::CHALLENGE_RESPONSE_NEEDED);

        SECTION("Challenge not solved 1") {
            CompleteAuthRequest caRequest(response.payload, name);
            Request request{{Request::Type::CHALLENGE, 0},
                            caRequest.serialize()};

            aliceCounter.setNumber(request);
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge not solved 2") {
            CompleteAuthRequest caRequest(
                    std::vector<unsigned char>(128, 10), name);
            Request request{{Request::Type::CHALLENGE, 0},
                            caRequest.serialize()};

            aliceCounter.setNumber(request);
            CHECK_THROWS(server.handleUserRequest(request));
        }

        SECTION("Challenge solved") {
            auto result = completeAlice(server, response.payload, name, Request::Type::CHALLENGE, aliceCounter);
            CHECK(result.header.type == Response::Type::OK);
        }
    }

    SECTION("Non-existing user") {
        AuthenticateRequest authRequest("bob", {});
        authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
        Request request{{Request::Type::LOGIN, 0}, authRequest.serialize()};

        CHECK_THROWS(server.handleUserRequest(request));
    }
    server.dropDatabase();
}

TEST_CASE("Delete & logout") {
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));
    std::string name = "alice";
    MessageNumberGenerator aliceCounter;

    auto response = registerAlice(server, name, aliceCounter);
    completeAlice(server, response.payload, name, Request::Type::CHALLENGE, aliceCounter);

    GenericRequest nameId{0, name};
    Request logoutRequest{{Request::Type::LOGOUT, 0}, nameId.serialize()};
    aliceCounter.setNumber(logoutRequest);

    auto logoutReponse = server.handleUserRequest(logoutRequest);
    CHECK(logoutReponse.header.type == Response::Type::OK);

    //login
    AuthenticateRequest authRequest("alice", {});
    authRequest.sessionKey = "323994cfb9da285a5d9642e1759b224a";
    Request login{{Request::Type::LOGIN, 0}, authRequest.serialize()};
    aliceCounter.setNumber(login);

    response = server.handleUserRequest(login);
    completeAlice(server, response.payload, name, Request::Type::CHALLENGE, aliceCounter);

    Request deleteUser{{Request::Type::REMOVE, 0}, nameId.serialize()};
    aliceCounter.setNumber(deleteUser);

    auto removeReponse = server.handleUserRequest(logoutRequest);
    CHECK(removeReponse.header.type == Response::Type::OK);
    //try to log in
    response = server.handleUserRequest(login);
    CHECK(response.header.type != Response::Type::OK);
    server.dropDatabase();
}

TEST_CASE("Get list") {
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));
    std::string name = "alice";
    MessageNumberGenerator counter;

    SECTION("Expected users in list") {
        SECTION("No users") { CHECK(server.getUsers("").empty()); }

        SECTION("Alice") {
            auto response = registerAlice(server, name, counter);
            completeAlice(server, response.payload, name, Request::Type::CHALLENGE, counter);

            CHECK(server.getUsers("") == std::vector<std::string>{"alice"});
        }

        SECTION("Lots of users") {
            for (int i = 0; i < 100; ++i) {
                MessageNumberGenerator tmpcounter;
                std::string name = "alice-" + std::to_string(i);
                auto response = registerAlice(server, name, tmpcounter);
                completeAlice(server, response.payload, name, Request::Type::CHALLENGE, tmpcounter);
            }
            CHECK(server.getUsers("").size() == 100);
        }
    }
    server.dropDatabase();
}

TEST_CASE("Key Bundles") {
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));
    uint32_t id = 3;
    
    KeyBundle<C25519> bundle;
    bundle.generateTimeStamp();
    bundle.preKeySingiture = {5};
    bundle.preKey = {6};
    bundle.identityKey = {7};
    bundle.oneTimeKeys = {{1}, {2}};

    server.updateKeyBundle({{Request::Type::KEY_BUNDLE_UPDATE, id}, bundle.serialize()});
    
    Response r = server.sendKeyBundle({{Request::Type::GET_RECEIVERS_BUNDLE, id}, GenericRequest{0, "jenda"}.serialize()});
    KeyBundle<C25519> received = KeyBundle<C25519>::deserialize(r.payload);
    CHECK(received.preKeySingiture == std::vector<unsigned char>{5});
    CHECK(received.preKey == std::vector<unsigned char>{6});
    CHECK(received.identityKey == std::vector<unsigned char>{7});
    CHECK(received.oneTimeKeys == std::vector<std::vector<unsigned char>>{{1}, {2}});

    r = server.sendKeyBundle({{Request::Type::GET_RECEIVERS_BUNDLE, id}, GenericRequest{0, "jenda"}.serialize()});
    received = KeyBundle<C25519>::deserialize(r.payload);
    CHECK(received.preKeySingiture == std::vector<unsigned char>{5});
    CHECK(received.preKey == std::vector<unsigned char>{6});
    CHECK(received.identityKey == std::vector<unsigned char>{7});
    CHECK(received.oneTimeKeys == std::vector<std::vector<unsigned char>>{{1}});

    r = server.sendKeyBundle({{Request::Type::GET_RECEIVERS_BUNDLE, id}, GenericRequest{0, "jenda"}.serialize()});
    received = KeyBundle<C25519>::deserialize(r.payload);
    CHECK(received.preKeySingiture == std::vector<unsigned char>{5});
    CHECK(received.preKey == std::vector<unsigned char>{6});
    CHECK(received.identityKey == std::vector<unsigned char>{7});
    CHECK(received.oneTimeKeys == std::vector<std::vector<unsigned char>>{});
    
    server.dropDatabase();
}