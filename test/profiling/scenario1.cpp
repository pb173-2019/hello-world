#include "conf.h"

#include "../../src/server/server.h"
#include "../../src/client/client.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/client/transmission_file_client.h"

using namespace helloworld;

//RUN SETUP TARGET FIRST TO GENERATE RSA KEYS !!!!
// THIS IS SEPARATED AS THE KEY GENERATING WOULD POLLUTE THE PROFILING

int main() {
    Server server;
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

//    std::vector<Client> users(); //not possible as the move cosntructor is not supported
//    if (ROUNDS < 6) throw Error("Invalid number of rounds."); //prevence from bad setup in conf.h
//
//    for (int i = 0; i < ROUNDS; i++) {
//        users.emplace_back("alice" + std::to_string(i), "alice" + std::to_string(i) + "priv.pem", "1234");
//        users[i].setTransmissionManager(std::make_unique<ClientFiles>(&users[i], users[i].name()));
//    }

    // -> ugly way: ROUNDSx instances  (BUT it certainly does improve the profiling measurement)
    Client c0{"1alice", "alice_0_priv.pem", "1234"};
    Client c1{"2alice", "alice_1_priv.pem", "1234"};
    Client c2{"3alice", "alice_2_priv.pem", "1234"};
    Client c3{"4alice", "alice_3_priv.pem", "1234"};
    Client c4{"5alice", "alice_4_priv.pem", "1234"};
    Client c5{"6alice", "alice_5_priv.pem", "1234"};
    Client c6{"7alice", "alice_6_priv.pem", "1234"};
    Client c7{"8alice", "alice_7_priv.pem", "1234"};
    Client c8{"9alice", "alice_8_priv.pem", "1234"};
    Client c9{"10alice", "alice_9_priv.pem", "1234"};
    Client c10{"11alice", "alice_10_priv.pem", "1234"};
    Client c11{"12alice", "alice_11_priv.pem", "1234"};
    Client c12{"13alice", "alice_12_priv.pem", "1234"};
    Client c13{"14alice", "alice_13_priv.pem", "1234"};
    Client c14{"15alice", "alice_14_priv.pem", "1234"};
    Client c15{"16alice", "alice_15_priv.pem", "1234"};
    Client c16{"17alice", "alice_16_priv.pem", "1234"};
    Client c17{"18alice", "alice_17_priv.pem", "1234"};
    Client c18{"19alice", "alice_18_priv.pem", "1234"};
    Client c19{"20alice", "alice_19_priv.pem", "1234"};

    c0.setTransmissionManager(std::make_unique<ClientFiles>(&c0, c0.name()));
    c1.setTransmissionManager(std::make_unique<ClientFiles>(&c1, c1.name()));
    c2.setTransmissionManager(std::make_unique<ClientFiles>(&c2, c2.name()));
    c3.setTransmissionManager(std::make_unique<ClientFiles>(&c3, c3.name()));
    c4.setTransmissionManager(std::make_unique<ClientFiles>(&c4, c4.name()));
    c5.setTransmissionManager(std::make_unique<ClientFiles>(&c5, c5.name()));
    c6.setTransmissionManager(std::make_unique<ClientFiles>(&c6, c6.name()));
    c7.setTransmissionManager(std::make_unique<ClientFiles>(&c7, c7.name()));
    c8.setTransmissionManager(std::make_unique<ClientFiles>(&c8, c8.name()));
    c9.setTransmissionManager(std::make_unique<ClientFiles>(&c9, c9.name()));
    c10.setTransmissionManager(std::make_unique<ClientFiles>(&c10, c10.name()));
    c11.setTransmissionManager(std::make_unique<ClientFiles>(&c11, c11.name()));
    c12.setTransmissionManager(std::make_unique<ClientFiles>(&c12, c12.name()));
    c13.setTransmissionManager(std::make_unique<ClientFiles>(&c13, c13.name()));
    c14.setTransmissionManager(std::make_unique<ClientFiles>(&c14, c14.name()));
    c15.setTransmissionManager(std::make_unique<ClientFiles>(&c15, c15.name()));
    c16.setTransmissionManager(std::make_unique<ClientFiles>(&c16, c16.name()));
    c17.setTransmissionManager(std::make_unique<ClientFiles>(&c17, c17.name()));
    c18.setTransmissionManager(std::make_unique<ClientFiles>(&c18, c18.name()));
    c19.setTransmissionManager(std::make_unique<ClientFiles>(&c19, c19.name()));

    if (ROUNDS != 20) throw Error("Invalid number of rounds."); //prevence from bad setup in conf.h

    std::vector<unsigned char> data{1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,3,1,2,1,32,1,3,2};

    std::vector<Client*> users;
    users.push_back(&c0);
    users.push_back(&c1);
    users.push_back(&c2);
    users.push_back(&c3);
    users.push_back(&c4);
    users.push_back(&c5);
    users.push_back(&c6);
    users.push_back(&c7);
    users.push_back(&c8);
    users.push_back(&c9);
    users.push_back(&c10);
    users.push_back(&c11);
    users.push_back(&c12);
    users.push_back(&c13);
    users.push_back(&c14);
    users.push_back(&c15);
    users.push_back(&c16);
    users.push_back(&c17);
    users.push_back(&c18);
    users.push_back(&c19);

    // ROUNDS times registration
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->createAccount("alice_" + std::to_string(i) + "_.pem");
        server.getRequest();
        users[i]->getResponse();
        server.getRequest();
        users[i]->getResponse();
        server.getRequest();
        users[i]->getResponse();
    }

    // ROUNDS (+1 initial msg) times ping-pong messaging
    users[0]->sendData(users[1]->getId(), data);
    server.getRequest();
    users[0]->getResponse();
    server.getRequest();
    users[1]->getResponse(); //SEGFAULT
    for (int i = 0; i < ROUNDS; i++) {
        int sender = i % 2 == 0 ? 1 : 0;
        int receiver = sender == 0 ? 1 : 0;

        users[sender]->sendData(users[receiver]->getId(), data);
        server.getRequest();
        users[receiver]->getResponse();
    }

    // ROUNDS (+1 initial msg) times ping-ping messaging
    users[2]->sendData(users[3]->getId(), data);
    server.getRequest();
    users[2]->getResponse();
    server.getRequest();
    users[3]->getResponse();
    for (int i = 0; i < ROUNDS; i++) {
        users[2]->sendData(users[3]->getId(), data);
        server.getRequest();
        users[3]->getResponse();
    }

    // ROUNDS times update key bundle
    for (int i = 0; i < ROUNDS; i++) {
        users[4]->sendKeysBundle();
        server.getRequest();
        users[4]->getResponse();
    }

    // ROUNDS times getOnline
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->sendGetOnline();
        server.getRequest();
        users[i]->getResponse();
    }

    // ROUNDS times get user by name
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->sendFindUsers("alice");
        server.getRequest();
        users[i]->getResponse();
    }

    // ROUNDS times logout
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->logout();
        server.getRequest();
        users[i]->getResponse();
    }

    // ROUNDS times login
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->login();
        server.getRequest();
        users[i]->getResponse();
        server.getRequest();
        users[i]->getResponse();
    }

    // ROUNDS times delete account
    for (int i = 0; i < ROUNDS; i++) {
        users[i]->deleteAccount();
        server.getRequest();
        users[i]->getResponse();
    }
    
    server.dropDatabase();
    ClientCleaner_Run();
}