#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/connection_manager.h"

#include "../../src/server/server.h"

using namespace helloworld;

TEST_CASE("Create key for alice") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "hunter2");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Scenario 1: create, logout, login, delete.") {
    Server server;

    Client client("alice", "server_pub.pem", "alice_priv.pem", "hunter2");
    client.createAccount("alice_pub.pem");

    std::cout << "server receives request\n";
    // server receives request
    server.getRequest();

    std::cout << "client receives challenge\n";
    // client receives challenge
    client.getResponse();

    std::cout << "server verifies challenge\n";
    // server verifies challenge
    server.getRequest();

    std::cout << "client obtains the final OK response\n";
    // client obtains the final OK response
    client.getResponse();

    client.logout();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getResponse();

    client.login();
    // server receives request
    server.getRequest();
    // client receives challenge
    client.getResponse();
    // server verifies challenge
    server.getRequest();
    // client obtains the final OK response
    client.getResponse();

    client.deleteAccount();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getResponse();
    server.dropDatabase();
}

void registerUserRoutine(Server& server, Client& client) {
    client.createAccount("alice_pub.pem");
    server.getRequest();
    client.getResponse();
    server.getRequest();
    client.getResponse();
}

template <typename inner>
bool checkContains(const std::vector<inner>& values, const inner& value) {
    for (const auto& item : values) {
        if (item == value)
            return true;
    }
    return false;
}

TEST_CASE("Scenario 2: getting users from database.") {
    Server server;

    Client alice("alice", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, alice);

    Client bob("bob", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    Client emily("emily", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, emily);

    Client lila("lila", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, lila);

    Client borek("borek", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, borek);

    Client lylibo("lylibo", "server_pub.pem", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, lylibo);

    borek.sendGetOnline();
    server.getRequest();
    borek.getResponse();

    CHECK(borek.getUsers().size() == 6);

    borek.sendFindUsers("li");
    server.getRequest();
    borek.getResponse();

    CHECK(checkContains<std::string>(borek.getUsers(), "alice"));
    CHECK(checkContains<std::string>(borek.getUsers(), "lylibo"));
    CHECK(checkContains<std::string>(borek.getUsers(), "lila"));
    CHECK(!checkContains<std::string>(borek.getUsers(), "emily"));
    CHECK(!checkContains<std::string>(borek.getUsers(), "bob"));
    server.dropDatabase();
}
