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

    Client client("alice", "alice_priv.pem", "hunter2");
    client.createAccount("alice_pub.pem");

    std::cout << "server receives request\n";
    // server receives request
    server.getRequest();

    std::cout << "client receives challenge\n";
    // client receives challenge
    client.getResponse();

    std::cout << "server verifies challenge\n";
    // server verifies challenge and asks for keys
    server.getRequest();

    std::cout << "client recieves Key Init Response\n";
    // client recieves Key Init Request
    client.getResponse();

    std::cout << "server recieve Key Update request and update keys in database\n";
    // server recieve Key Update request and update keys in database
    server.getRequest();

    std::cout << "client recieves final ok response";
    // Final OK response
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
    server.getRequest();
    client.getResponse();
}


bool checkContains(const std::map<uint32_t, std::string>& values, const std::string& value) {
    for (const auto& item : values) {
        if (item.second == value)
            return true;
    }
    return false;
}

TEST_CASE("Scenario 2: getting users from database.") {
    Server server;

    Client alice("alice", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, alice);

    Client bob("bob", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    Client emily("emily","alice_priv.pem", "hunter2");
    registerUserRoutine(server, emily);

    Client lila("lila", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, lila);

    Client borek("borek", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, borek);

    Client lylibo("lylibo", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, lylibo);

    borek.sendGetOnline();
    server.getRequest();
    borek.getResponse();

    CHECK(borek.getUsers().size() == 6);

    borek.sendFindUsers("li");
    server.getRequest();
    borek.getResponse();

    CHECK(checkContains(borek.getUsers(), "alice"));
    CHECK(checkContains(borek.getUsers(), "lylibo"));
    CHECK(checkContains(borek.getUsers(), "lila"));
    CHECK(!checkContains(borek.getUsers(), "emily"));
    CHECK(!checkContains(borek.getUsers(), "bob"));
    server.dropDatabase();
}

TEST_CASE("Incorrect authentications") {
    Server server;
    Client alice("alice", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, alice);
    Client bob("bob", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    Client client1("alice", "alice_priv.pem", "hunter2");
    //registrates when user logged with that exact username
    server.simulateNewChannel("alice");
    client1.createAccount("alice_pub.pem");
    // server receives request
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client1.getResponse());


    //registrates when username exists, but not logged in
    server.logout("alice");
    client1.createAccount("alice_pub.pem");
    // server receives request
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client1.getResponse());

    server.simulateNewChannel("bob");
    Client client2("bob", "alice_priv.pem", "hunter2");
    client2.login();
    // server receives request //TODO fails
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client2.getResponse());
    server.dropDatabase();
}

TEST_CASE("Messages exchange - two users online, establish the X3DH shared secret connection") {
    Server server;
    Client alice("alice", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, alice);
    Client bob("bob", "alice_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    alice.sendGetOnline();

    //server receives request
    server.getRequest();
    //client obtains the online users
    alice.getResponse();

    uint32_t id;
    //get bob id, maybe reverse map and make it name -> id
    for (auto it : alice.getUsers())
        if (it.second == "bob")
            id = it.first;

    //national secret message!
    alice.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

    //server receives get bob bundle request
    server.getRequest();
    //alice receives bundle and actually sends data
    alice.getResponse();
    //server forwards as bob is online
    server.getRequest();
    //bob gets message
    bob.getResponse();

    SendData received = bob.getMessage();
    CHECK(received.from == "alice");
    CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

    server.dropDatabase();
}