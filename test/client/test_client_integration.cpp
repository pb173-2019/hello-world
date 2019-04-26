#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/connection_manager.h"

#include "../../src/server/server.h"
#include "../../src/client/transmission_file_client.h"

using namespace helloworld;

TEST_CASE("Create key for aliceabc") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("aliceabc_priv.pem", "hunter2");
    keygen.savePublicKey("aliceabc_pub.pem");

    Server server;
    Server::setTest(false); // testing the real performance -> turn off
    server.dropDatabase(); //prevents database data from other testing
}

TEST_CASE("Scenario 1: create, logout, login, delete.") {
    Network::setEnabled(true);

    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    Client client("aliceabc", "aliceabc_priv.pem", "hunter2");
    client.setTransmissionManager(std::make_unique<ClientFiles>(&client, client.name()));

    client.createAccount("aliceabc_pub.pem");

    client.logout();

    client.login();

    client.deleteAccount();

    server.dropDatabase();
    Network::setEnabled(false);
}


bool checkContains(const std::map<uint32_t, std::string>& values, const std::string& value) {
    for (const auto& item : values) {
        if (item.second == value)
            return true;
    }
    return false;
}

TEST_CASE("Scenario 2: getting users from database.") {
    Network::setEnabled(true);
    Network::setProblematic(false);

    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    aliceabc.setTransmissionManager(std::make_unique<ClientFiles>(&aliceabc, aliceabc.name()));
    aliceabc.createAccount("aliceabc_pub.pem");

    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));
    bob.createAccount("aliceabc_pub.pem");

    Client emily("emily","aliceabc_priv.pem", "hunter2");
    emily.setTransmissionManager(std::make_unique<ClientFiles>(&emily, emily.name()));
    emily.createAccount("aliceabc_pub.pem");

    Client lila("lila", "aliceabc_priv.pem", "hunter2");
    lila.setTransmissionManager(std::make_unique<ClientFiles>(&lila, lila.name()));
    lila.createAccount("aliceabc_pub.pem");

    Client borek("borek", "aliceabc_priv.pem", "hunter2");
    borek.setTransmissionManager(std::make_unique<ClientFiles>(&borek, borek.name()));
    borek.createAccount("aliceabc_pub.pem");

    Client lylibo("lylibo", "aliceabc_priv.pem", "hunter2");
    lylibo.setTransmissionManager(std::make_unique<ClientFiles>(&lylibo, lylibo.name()));
    lylibo.createAccount("aliceabc_pub.pem");

    borek.sendGetOnline();

    CHECK(borek.getUsers().size() == 6);

    borek.sendFindUsers("li");

    CHECK(checkContains(borek.getUsers(), "aliceabc"));
    CHECK(checkContains(borek.getUsers(), "lylibo"));
    CHECK(checkContains(borek.getUsers(), "lila"));
    CHECK(!checkContains(borek.getUsers(), "emily"));
    CHECK(!checkContains(borek.getUsers(), "bob"));
    server.dropDatabase();
    Network::setEnabled(false);

}

TEST_CASE("Incorrect authentications") {
    Network::setEnabled(true);

    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    aliceabc.setTransmissionManager(std::make_unique<ClientFiles>(&aliceabc, aliceabc.name()));

    aliceabc.createAccount("aliceabc_pub.pem");
    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));

    bob.createAccount("aliceabc_pub.pem");

    //registrates when user logged with that exact username
    Client client1("aliceabc", "aliceabc_priv.pem", "hunter2");
    client1.setTransmissionManager(std::make_unique<ClientFiles>(&client1, client1.name()));

    server.simulateNewChannel("aliceabc");
    CHECK_THROWS(client1.createAccount("aliceabc_pub.pem"));

    //registrates when username exists, but not logged in
    server.logout("aliceabc");
    CHECK_THROWS(client1.createAccount("aliceabc_pub.pem"));

    server.simulateNewChannel("bob");
    Client client2("bob", "aliceabc_priv.pem", "hunter2");
    client2.setTransmissionManager(std::make_unique<ClientFiles>(&client2, client2.name()));

    CHECK_THROWS(client2.login());

    server.dropDatabase();
    Network::setEnabled(false);

    ClientCleaner_Run();
}


TEST_CASE("Messages exchange - two users online, establish the X3DH shared secret connection") {
    Network::setEnabled(true);
    Network::setProblematic(false);

    Server server;

    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    Client aliceabc("aliceabc", "aliceabc_priv.pem", "hunter2");
    aliceabc.setTransmissionManager(std::make_unique<ClientFiles>(&aliceabc, aliceabc.name()));
    aliceabc.createAccount("aliceabc_pub.pem");
    Client bob("bob", "aliceabc_priv.pem", "hunter2");
    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));
    bob.createAccount("aliceabc_pub.pem");

    aliceabc.sendGetOnline();

    uint32_t id = 0;
    //get bob id, maybe reverse map and make it name -> id
    for (auto it : aliceabc.getUsers())
        if (it.second == "bob")
            id = it.first;

    REQUIRE(id == bob.getId());

    SECTION("aliceabc uses the avaliable key from bundle of one time keys") {
        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});
    }

    SECTION("Bob updates his bundle, but is able to decrypt the message anyway") {
        bob.sendKeysBundle();

        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});
    }

    SECTION("Some mischievous user has emptied the one time keys") {
        for (int i = 0; i < 20; ++i) {
            //no message, the client attempts to send no existing data (file) with the key bundle
            CHECK_THROWS(aliceabc.requestKeyBundle(id));
        }

        //national secret message!
        aliceabc.sendData(id, std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        SendData received = bob.getMessage();
        CHECK(received.from == "aliceabc");
        CHECK(received.data == std::vector<unsigned char>{'a', 'h', 'o', 'j', 'b', 'o', 'b', 'e'});

        uint64_t lastTimeStamp = server.getDatabase().getBundleTimestamp(bob.getId());
        std::vector<unsigned char> oldBundle = server.getDatabase().selectBundle(bob.getId());

        //bob now goes offline, and when logs in, the server requests key update / the onetime keys were gone
        bob.logout();

        uint64_t timestampOfLogin = getTimestampOf(nullptr);

        bob.login();

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
    Network::setEnabled(false);

    ClientCleaner_Run();
}
