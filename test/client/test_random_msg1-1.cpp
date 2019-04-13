#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/server.h"
#include "../../src/client/transmission_file_client.h"
using namespace helloworld;
// will always start from 1
static bool alice_on = true;
static bool bob_on = true;

static constexpr size_t SEND_DATA = 0;
static constexpr size_t RECEIVE = 1;
static constexpr size_t LOGIN = 2;
static constexpr size_t LOGOUT = 3;
static constexpr size_t REGISTER = 4;
static constexpr size_t DELETE_ACC = 5;

std::ostream& operator<<(std::ostream& in, const std::vector<unsigned char>& data) {
    for (unsigned char c : data) {
        in << static_cast<int>(c) << ',';
    }
    in << "\n";
    return in;
}

void callRandomMethod(Client& alice, Client& bob, size_t rand, Random& random, bool checkValid) {

    Client& performing = random.getBounded(0, 13) % 2 == 0 ? alice : bob;
    uint32_t other_id = (performing.getId() == 1) ? 2 : 1;

    if (checkValid) {
        bool on = (other_id == 1) ? bob_on : alice_on;
        if (on && (rand == LOGIN || rand == REGISTER)) {
            rand = SEND_DATA;
        }
        if (!on && (rand != LOGIN && rand != REGISTER))
            rand = LOGIN;
    }

    switch(rand) {
        case SEND_DATA: {
            std::vector<unsigned char> data = random.get(random.getBounded(0, 500));
            std::cout << "Client id " + std::to_string(performing.getId()) + " sending data to id " + std::to_string(other_id) << "...";
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
            std::cout << "Client id " + std::to_string(performing.getId()) + " asks server to check incomming messages...";
            performing.checkForMessages();
            if (performing.getMessage().from.empty()) {
                std::cout << "\ndone: Nothing received.\n";
            } else {
                std::cout << "\ndone. Old received: " << performing.getMessage().data;
                performing.getMessage().from = "";
            }
            break;
        }

        case LOGIN: {
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to log-in...";
            performing.login();
            std::cout << " done.\n";
            if (performing.getId() == 1) alice_on = true; else bob_on = true;
            if (performing.getMessage().from.empty()) {
                std::cout << "\nNothing received.\n";
            } else {
                std::cout << "\nOld received: " << performing.getMessage().data;
                performing.getMessage().from = "";
            }
            break;
        }

        case LOGOUT: {
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to log-out...";
            performing.logout();
            std::cout << " done.\n";
            if (performing.getId() == 1) alice_on = false; else bob_on = false;
            break;
        }

        case REGISTER: {
            std::string pubeky = other_id == 1 ? "bob_messaging_pub.pem" : "alice_messaging_pub.pem";
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to register...";
            performing.createAccount(pubeky);
            std::cout << " done.\n";
            break;
        }

        case DELETE_ACC: {
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to remove account...";
            performing.deleteAccount();
            std::cout << " done.\n";
            break;
        }

        default:
            break;
    }
}

//three phases - messaging randomly, messaging + connections, messaging + lost messages
TEST_CASE("Create keys") {
    RSAKeyGen alice;
    alice.savePrivateKeyPassword("alice_messaging.pem", "123456");
    alice.savePublicKey("alice_messaging_pub.pem");

    RSAKeyGen bob;
    bob.savePrivateKeyPassword("bob_messaging.pem", "123456");
    bob.savePublicKey("bob_messaging_pub.pem");
}

TEST_CASE("Random testing 1:1 messaging") {
    Network::setEnabled(true);

    Server server;
    Random random;

    Client alice("alice", "alice_messaging.pem", "123456");
    alice.setTransmissionManager(std::make_unique<ClientFiles>(&alice, alice.name()));
    Client bob("bob", "bob_messaging.pem", "123456");
    bob.setTransmissionManager(std::make_unique<ClientFiles>(&bob, bob.name()));

    alice.createAccount("alice_messaging_pub.pem");
    bob.createAccount("bob_messaging_pub.pem");

    SECTION("Just online users") {
        std::cout << "--------------------------------------\n"
                     "----------SIMPLE SENDING MSGS---------\n"
                     "--------------------------------------\n";

        for (int i = 0; i < 50; i++) {
            std::cout << "Round: " << std::to_string(i) << "\n";
            callRandomMethod(alice, bob, SEND_DATA, random, false);
            std::cout << "------\n\n";
        }
    }

    SECTION("Users may go randomly on/off") { // discovered problem: requesting msg from server whn multiple stored returns nothing
        std::cout << "--------------------------------------\n"
                     "------------RANDOMLY ON/OFF-----------\n"
                     "--------------------------------------\n";

        for (int i = 0; i < 70; i++) {
            std::cout << "Round: " << std::to_string(i) << "\n";
            size_t randomAction = random.getBounded(SEND_DATA, LOGOUT + 1);

            callRandomMethod(alice, bob, randomAction, random, true);
            std::cout << "------\n\n";
        }
    }

    //in main: commented -> will fail
//    SECTION("The messages are delayed") {
//        std::cout << "--------------------------------------\n"
//                     "-----------DELAYED MESSAGES-----------\n"
//                     "--------------------------------------\n";
//        bool problem = false;
//
//        for (int i = 0; i < 50; i++) {
//            if (random.getBounded(0, 10) < 6) {
//                if (problem) goto test;
//
//                problem = true;
//                Network::setProblematic(true);
//                std::cout << "messages delayed\n";
//            } else {
//                if (!problem) goto test;
//
//                problem = false;
//                Network::setProblematic(false);
//                std::cout << "_______________messages enabled, releasing messages:_______________\n";
//                const std::string* sender = Network::getBlockedMsgSender();
//                int ii = 1;
//                while (sender != nullptr) {
//                    Client& receiver = (*sender == "alice.tcp") ? bob : alice;
//                    Network::release();
//
//                    if (receiver.getMessage().from.empty()) {
//                        std::cout << std::to_string(ii) << ": nothing received!!!\n";
//                    } else {
//                        std::cout << std::to_string(ii) << ": " << receiver.getMessage().data;
//                        receiver.getMessage().from = "";
//                    }
//                    sender = Network::getBlockedMsgSender();
//                    ii++;
//                }
//                std::cout << "_______________testing continues_______________\n\n";
//            }
//
//            test:
//
//            std::cout << "Round: " << std::to_string(i) << "\n";
//            callRandomMethod(alice, bob, SEND_DATA, random, false);
//            std::cout << "------\n\n";
//        }
//    }

    //valid testing?

//    SECTION("Random actions") {
//        std::cout << "--------------------------------------\n"
//                     "-----------RANDOMLY DO STUFF----------\n"
//                     "--------------------------------------\n";
//
//        for (int i = 0; i < 70; i++) {
//            try {
//                std::cout << "Round: " << std::to_string(i) << "\n";
//                size_t randomAction = random.getBounded(SEND_DATA, DELETE_ACC + 1);
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