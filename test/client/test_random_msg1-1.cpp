#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/server.h"

using namespace helloworld;
// will always start from 1
static constexpr int alice_id = 1;
static constexpr int bob_id = 2;

static constexpr size_t SEND_DATA = 0;
static constexpr size_t LOGIN = 1;
static constexpr size_t LOGOUT = 2;
static constexpr size_t REGISTER = 3;
static constexpr size_t DELETE_ACC = 4;

std::ostream& operator<<(std::ostream& in, const std::vector<unsigned char>& data) {
    for (unsigned char c : data) {
        in << static_cast<int>(c) << ',';
    }
    in << "\n";
    return in;
}

void callRandomMethod(Client& alice, Client& bob, size_t rand, Random& random) {

    Client& performing = random.getBounded(0, 13) % 2 == 0 ? alice : bob;
    uint32_t other_id = (performing.getId() == 1) ? 2 : 1;

    switch(rand) {
        case SEND_DATA: {
            std::vector<unsigned char> data = random.get(random.getBounded(0, 500));
            std::cout << "Client id " + std::to_string(performing.getId()) + " sending data to id " + std::to_string(other_id) << "...";
            std::cout << "\nsending: " << data;
            performing.sendData(other_id, data);
            std::cout << " done. Received: " << (other_id == 1 ? alice : bob).getMessage().data;
            break;
        }

        case LOGIN: {
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to log-in...";
            performing.login();
            std::cout << " done.\n";
            break;
        }

        case LOGOUT: {
            std::cout << "Client id " + std::to_string(performing.getId()) + " attempts to log-out...";
            performing.logout();
            std::cout << " done.\n";
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

TEST_CASE("The users are logged in & randomly messages earch other") {
    Network::setEnabled(true);

    Server server;

    Client alice("alice", "alice_messaging.pem", "123456");
    Client bob("bob", "bob_messaging.pem", "123456");

    alice.createAccount("alice_messaging_pub.pem");
    bob.createAccount("bob_messaging_pub.pem");

    Random random;

    for (int i = 0; i < 50; i++) {
        std::cout << "Round: " << std::to_string(i) << "\n";
        callRandomMethod(alice, bob, SEND_DATA, random);
        std::cout << "------\n\n";
    }

    server.dropDatabase();
    ClientCleaner_Run();
}

TEST_CASE("Clear keys") {
    remove("alice_messaging.pem");
    remove("alice_messaging_pub.pem");
    remove("bob_messaging.pem");
    remove("bob_messaging_pub.pem");
}