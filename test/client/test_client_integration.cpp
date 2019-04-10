#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/connection_manager.h"

#include "../../src/server/server.h"

using namespace helloworld;

TEST_CASE("Create key for aliceabc") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("aliceabc_priv.pem", "hunter2");
    keygen.savePublicKey("aliceabc_pub.pem");
}

TEST_CASE("Scenario 1: create, logout, login, delete.") {
    Server server;

    Client client("aliceabc", "aliceabc_priv.pem", "hunter2");
    client.createAccount("aliceabc_pub.pem");

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
    client.createAccount("aliceabc_pub.pem");
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

    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, aliceabc);

    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    Client emily("emily","aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, emily);

    Client lila("lila", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, lila);

    Client borek("borek", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, borek);

    Client lylibo("lylibo", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, lylibo);

    borek.sendGetOnline();
    server.getRequest();
    borek.getResponse();

    CHECK(borek.getUsers().size() == 6);

    borek.sendFindUsers("li");
    server.getRequest();
    borek.getResponse();

    CHECK(checkContains(borek.getUsers(), "aliceabc"));
    CHECK(checkContains(borek.getUsers(), "lylibo"));
    CHECK(checkContains(borek.getUsers(), "lila"));
    CHECK(!checkContains(borek.getUsers(), "emily"));
    CHECK(!checkContains(borek.getUsers(), "bob"));
    server.dropDatabase();
}

TEST_CASE("Incorrect authentications") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("aliceabc_priv.pem", "hunter2");
    keygen.savePublicKey("aliceabc_pub.pem");
    
    Server server;
    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, aliceabc);
    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    Client client1("aliceabc", "aliceabc_priv.pem", "hunter2");
    //registrates when user logged with that exact username
    server.simulateNewChannel("aliceabc");
    client1.createAccount("aliceabc_pub.pem");
    // server receives request
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client1.getResponse());


    //registrates when username exists, but not logged in
    server.logout("aliceabc");
    client1.createAccount("aliceabc_pub.pem");
    // server receives request
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client1.getResponse());

    server.simulateNewChannel("bob");
    Client client2("bob", "aliceabc_priv.pem", "hunter2");
    client2.login();
    // server receives request
    server.getRequest();
    // client receives challenge
    CHECK_THROWS(client2.getResponse());
    server.dropDatabase();
}

void emptyOneTimeKeysRoutine(Server& server, Client& client, uint32_t id) {
    client.requestKeyBundle(id);
    server.getRequest();
    //no message, the client attempts to send no existing data (file) with the key bundle
    CHECK_THROWS(client.getResponse());
}

TEST_CASE("Messages exchange - two users online, establish the X3DH shared secret connection") {
    Server server;
    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, aliceabc);
    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    registerUserRoutine(server, bob);

    aliceabc.sendGetOnline();

    //server receives request
    server.getRequest();
    //client obtains the online users
    aliceabc.getResponse();

    uint32_t id;
    //get bob id, maybe reverse map and make it name -> id
    for (auto it : aliceabc.getUsers())
        if (it.second == "bob")
            id = it.first;

    SECTION("aliceabc uses the avaliable key from bundle of one time keys") {
        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        //server receives get bob bundle request
        std::cout << "server receives get bob bundle request\n";
        server.getRequest();
        //aliceabc receives bundle and actually sends data
        std::cout << "aliceabc receives bundle and actually sends data\n";
        aliceabc.getResponse();
        //server forwards as bob is online
        std::cout << "server forwards as bob is online\n";
        server.getRequest();
        //bob gets message
        std::cout << "bob gets message\n";
        bob.getResponse();

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});
    }

    SECTION("Bob updates his bundle, but is able to decrypt the message anyway") {
        bob.sendKeysBundle();
        //server receves & stores the data
        server.getRequest();
        //bob receives OK
        bob.getResponse();
        
        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});
        //server receives get bob bundle request
        server.getRequest();
        //aliceabc receives bundle and actually sends data
        aliceabc.getResponse();
        //server forwards as bob is online
        server.getRequest();
        //bob gets message & parses the message using OLD key files
        bob.getResponse();

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});
    }

    SECTION("Some mischievous user has emptied the one time keys") {
        for (int i = 0; i < 20; ++i) {
            emptyOneTimeKeysRoutine(server, aliceabc, id);
        }
        
        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        //server receives get bob bundle request
        server.getRequest();
        //aliceabc receives bundle and actually sends data
        aliceabc.getResponse();
        //server forwards as bob is online
        server.getRequest();
        //bob gets message
        bob.getResponse();

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        uint64_t lastTimeStamp = server.getDatabase().getBundleTimestamp(bob.getId());
        std::vector<unsigned char> oldBundle = server.getDatabase().selectBundle(bob.getId());

        //bob now goes offline, and when logs in, the server requests key update / the onetime keys were gone
        bob.logout();
        server.getRequest();
        bob.getResponse();

        uint64_t timestampOfLogin = getTimestampOf(nullptr);

        bob.login();
        // server receives request
        server.getRequest();
        // client receives challenge
        bob.getResponse();
        // server verifies & sends the key update needed
        server.getRequest();
        //bob sends keys
        bob.getResponse();
        //server stores keys & sends OK
        server.getRequest();
        // client receives OK
        bob.getResponse();

        uint64_t newTimeStamp = server.getDatabase().getBundleTimestamp(bob.getId());
        std::vector<unsigned char> newBundle = server.getDatabase().selectBundle(bob.getId());

        KeyBundle<C25519> oldKeys = KeyBundle<C25519>::deserialize(oldBundle);
        KeyBundle<C25519> newKeys = KeyBundle<C25519>::deserialize(newBundle);

        CHECK(lastTimeStamp == 1);
        CHECK(newTimeStamp > lastTimeStamp);
        CHECK(newTimeStamp == timestampOfLogin); //timestamp varies once a hour


        CHECK(oldKeys.oneTimeKeys.size() == 0);
        CHECK(newKeys.oneTimeKeys.size() == 20);

        CHECK(oldKeys.identityKey == newKeys.identityKey);
        CHECK(oldKeys.preKeySingiture != newKeys.preKeySingiture);
        CHECK(oldKeys.preKey != newKeys.preKey);
        //CHECK(oldKeys.timestamp < newKeys.timestamp); will not work as the timestamp changes a hour
    }
    server.dropDatabase();
}
