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
    client.getRequest();

    std::cout << "server verifies challenge\n";
    // server verifies challenge
    server.getRequest();

    std::cout << "client obtains the final OK response\n";
    // client obtains the final OK response
    client.getRequest();

    client.logout();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();

    client.login();
    // server receives request
    server.getRequest();
    // client receives challenge
    client.getRequest();
    // server verifies challenge
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();

    client.deleteAccount();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();
    server.dropDatabase();
}
