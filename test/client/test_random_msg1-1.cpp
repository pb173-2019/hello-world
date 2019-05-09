#include <unordered_map>

#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/client/transmission_file_client.h"
#include "../../src/server/server.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/utils.h"

using namespace helloworld;
static bool alice_on = true;
static bool bob_on = true;

static size_t SQLid = 0;

static constexpr size_t SEND_DATA = 0;
static constexpr size_t RECEIVE = 1;
static constexpr size_t LOGIN = 2;
static constexpr size_t LOGOUT = 3;
static constexpr size_t REGISTER = 4;
static constexpr size_t DELETE_ACC = 5;

void resetTest() {
    Server server("Hello, world! 2.0 password");
    server.dropDatabase();
    SQLid = 0;
}

bool callRandomMethod(std::unordered_map<Client*, uint32_t>& ids, Client& alice,
                      Client& bob, size_t rand, Random& random,
                      bool checkValid) {
    auto x = random.getBounded(0, 13) % 2;
    Client& performing = x == 0 ? alice : bob;
    Client& other = x == 1 ? alice : bob;

    uint32_t other_id = (&performing == &alice) ? ids[&bob] : ids[&alice];

    if (checkValid) {
        bool on = (performing.getId() != 0);
        if (on && (rand == LOGIN || rand == REGISTER)) {
            rand = SEND_DATA;
        } else if (ids[&performing] == 0)
            rand = REGISTER;
        else if (!on)
            rand = LOGIN;
    }

    switch (rand) {
        case SEND_DATA: {
            if (performing.getId() == 0) return false;
            if (other_id == 0) return false;    // deleted account
            std::vector<unsigned char> data =
                random.get(random.getBounded(0, 500));
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " sending data to id " + std::to_string(other_id)
                      << "...";
            std::cout << "\nsending: " << data;
            performing.sendData(other_id, data);
            Client& other = other_id == 1 ? alice : bob;
            if (other.getMessage().from.empty()) {
                std::cout << "\ndone: Not received.\n";
            } else {
                std::cout << "\ndone. Received: " << other.getMessage().data;
                other.getMessage().from = "";
            }
            break;
        }

        case RECEIVE: {
            if (performing.getId() == 0) return false;
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " asks server to check incomming messages...";
            performing.checkForMessages();
            if (performing.getMessage().from.empty()) {
                std::cout << "\ndone: Nothing received.\n";
            } else {
                std::cout << "\ndone. Old received: "
                          << performing.getMessage().data;
                performing.getMessage().from = "";
            }
            break;
        }

        case LOGIN: {
            if (performing.getId() != 0) return false;
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " attempts to log-in...";

            performing.login();
            std::cout << " done.\n";
            if (performing.getId() == 1)
                alice_on = true;
            else
                bob_on = true;
            if (performing.getMessage().from.empty()) {
                std::cout << "\nNothing received.\n";
            } else {
                std::cout << "\nOld received: " << performing.getMessage().data;
                performing.getMessage().from = "";
            }
            break;
        }

        case LOGOUT: {
            if (performing.getId() == 0) return false;
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " attempts to log-out...";
            performing.logout();
            std::cout << " done.\n";
            if (performing.getId() == 1)
                alice_on = false;
            else
                bob_on = false;
            break;
        }

        case REGISTER: {
            if (ids[&performing] != 0) return false;
            std::string pubeky = other_id == 1 ? "bob_messaging_pub.pem"
                                               : "alice_messaging_pub.pem";
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " attempts to register...";
            performing.createAccount(pubeky);
            ++SQLid;
            ids[&performing] = static_cast<uint32_t>(SQLid);
            std::cout << " done.\n";
            break;
        }

        case DELETE_ACC: {
            if (performing.getId() == 0) return false;
            ids[&performing] = 0;
            std::cout << "Client id " + std::to_string(ids[&performing]) +
                             " attempts to remove account...";
            performing.deleteAccount();
            std::cout << " done.\n";
            break;
        }

        default:
            break;
    }
    return true;
}

// three phases - messaging randomly, messaging + connections, messaging + lost
// messages
TEST_CASE("Create keys") {
    RSAKeyGen alice;
    alice.savePrivateKeyPassword("alice_messaging.pem", "12345678");
    alice.savePublicKey("alice_messaging_pub.pem");

    RSAKeyGen bob;
    bob.savePrivateKeyPassword("bob_messaging.pem", "12345678");
    bob.savePublicKey("bob_messaging_pub.pem");

    Server::setTest(false);
}

TEST_CASE("Problematic scenarios explicitly performed, found by test below") {
    Network::setEnabled(true);
    Network::setProblematic(false);

    Server server("Hello, world! 2.0 password");
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    Random random;

    Client alice("alice", "alice_messaging.pem", "12345678");
    alice.setTransmissionManager(
        std::make_unique<ClientFiles>(&alice, alice.name()));
    Client bob("bob", "bob_messaging.pem", "12345678");
    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));

    alice.createAccount("alice_messaging_pub.pem");
    bob.createAccount("bob_messaging_pub.pem");

    SECTION(
        "User sends data while other offline, when comes online the sender "
        "thinks the connection is established while other does not.") {
        uint32_t id = alice.getId();
        alice.logout();
        bob.sendData(id, {1, 2, 3});
        alice.login();
        CHECK(alice.getMessage().data == std::vector<unsigned char>{1, 2, 3});
        alice.sendData(bob.getId(),
                       {1});    // <-- here **NEW** X3DH while bob has old one
    }

    SECTION("Multiple offline messages") {
        uint32_t id = bob.getId();
        bob.logout();
        alice.sendData(id, {1, 2, 3});
        alice.sendData(id, {1, 2, 3});
        alice.sendData(id, {1, 2, 3});

        bob.login();
        CHECK(bob.getMessage().data.size() >= 3);
    }

    server.dropDatabase();
}

TEST_CASE("Random testing 1:1 messaging") {
    resetTest();
    Network::setEnabled(true);

    Server server("Hello, world! 2.0 password");
    server.setLogging(
        [](const std::string& str) { std::cout << "##" << str << std::endl; });
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));
    Random random;

    Server::setTest(true);
    Client::setTest(true);

    Client alice("alice", "alice_messaging.pem", "12345678");

    alice.setTransmissionManager(
        std::make_unique<ClientFiles>(&alice, alice.name()));
    Client bob("bob", "bob_messaging.pem", "12345678");

    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));

    alice.createAccount("alice_messaging_pub.pem");
    ++SQLid;
    bob.createAccount("bob_messaging_pub.pem");
    ++SQLid;
    std::unordered_map<Client*, uint32_t> ids = {{&bob, bob.getId()},
                                                 {&alice, alice.getId()}};

    SECTION("Just online users") {
        std::cout << "--------------------------------------\n"
                     "----------SIMPLE SENDING MSGS---------\n"
                     "--------------------------------------\n";

        for (int i = 0; i < 50; i++) {
            std::cout << "Round: " << std::to_string(i) << "\n";
            while (!callRandomMethod(ids, alice, bob, SEND_DATA, random, false))
                ;
            std::cout << "------\n\n";
        }
    }

    SECTION(
        "Users may go randomly on/off") {    // discovered problem: requesting
                                             // msg from server whn multiple
                                             // stored returns nothing
        std::cout << "--------------------------------------\n"
                     "------------RANDOMLY ON/OFF-----------\n"
                     "--------------------------------------\n";

        for (int i = 0; i < 70; i++) {
            std::cout << "Round: " << std::to_string(i) << "\n";
            size_t randomAction = random.getBounded(SEND_DATA, LOGOUT + 1);

            while (
                !callRandomMethod(ids, alice, bob, randomAction, random, true))
                randomAction = random.getBounded(SEND_DATA, LOGOUT + 1);
            std::cout << "------\n\n";
        }
    }

    SECTION("The messages are delayed") {
        std::cout << "--------------------------------------\n"
                     "-----------DELAYED MESSAGES-----------\n"
                     "--------------------------------------\n";
        // TODO: problem when 1->2; 2->1; released
        bool problem = false;

        for (int i = 0; i < 50; i++) {
            if (random.getBounded(0, 10) < 6) {
                if (problem) goto test;

                problem = true;
                Network::setProblematic(true);
                std::cout << "messages delayed\n";
            } else {
                if (!problem) goto test;

                problem = false;
                Network::setProblematic(false);
                std::cout << "_______________messages enabled, releasing "
                             "messages:_______________\n";
                const std::string* sender = Network::getBlockedMsgSender();
                int ii = 1;
                while (sender != nullptr) {
                    Client& receiver = (*sender == "alice.tcp") ? bob : alice;
                    Network::release();
                    if (receiver.getMessage().from.empty()) {
                        std::cout << std::to_string(ii)
                                  << ": nothing received!!!\n";
                    } else {
                        std::cout << std::to_string(ii) << ": "
                                  << receiver.getMessage().data;
                        receiver.getMessage().from = "";
                    }
                    sender = Network::getBlockedMsgSender();
                    ii++;
                }
                std::cout
                    << "_______________testing continues_______________\n\n";
            }

        test:

            std::cout << "Round: " << std::to_string(i) << "\n";
            callRandomMethod(ids, alice, bob, SEND_DATA, random, false);
            std::cout << "------\n\n";
        }
        std::cout << "1-1 testing finished.\n\n";
    }

    // valid testing?

    //    SECTION("Random actions") {
    //        std::cout << "--------------------------------------\n"
    //                     "-----------RANDOMLY DO STUFF----------\n"
    //                     "--------------------------------------\n";
    //
    //        for (int i = 0; i < 70; i++) {
    //            try {
    //                std::cout << "Round: " << std::to_string(i) << "\n";
    //                size_t randomAction = random.getBounded(SEND_DATA,
    //                DELETE_ACC + 1);
    //
    //                callRandomMethod(alice, bob, randomAction, random, true);
    //                std::cout << "------\n\n";
    //            } catch (std::exception& ex) {
    //                std::cout << "ERROR: " << ex.what() << "\n";
    //            }
    //        }
    //    }

    server.dropDatabase();
}

TEST_CASE("Clear keys") {
    remove("alice_messaging.pem");
    remove("alice_messaging_pub.pem");
    remove("bob_messaging.pem");
    remove("bob_messaging_pub.pem");
    ClientCleaner_Run();
}
