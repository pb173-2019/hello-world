#include "catch.hpp"

#include <chrono>
#include <random>
#include "../../src/client/client.h"
#include "../../src/client/transmission_file_client.h"
#include "../../src/server/server.h"
#include "../../src/server/transmission_file_server.h"

using namespace helloworld;

class ClientAdapter {
    std::string _name;
    std::string _password;
    std::string _privateKeyName;
    std::string _publicKeyName;

   public:
    std::unique_ptr<Client> client;

    ClientAdapter(std::string name)
        : _name(std::move(name)),
          _password("password"),
          _privateKeyName(_name + "_messaging.pem"),
          _publicKeyName(createPublicKeys()),
          client(std::make_unique<Client>(_name, _privateKeyName, _password)) {
        client->setTransmissionManager(
            std::make_unique<ClientFiles>(client.get(), client->name()));
    }

    std::string createPublicKeys() {
        RSAKeyGen keygen;
        keygen.savePrivateKeyPassword(_privateKeyName, _password);
        keygen.savePublicKey(_name + "_messaging.pub");

        return _name + "_messaging.pub";
    }

    void createAccount() { client->createAccount(_publicKeyName); }
};

class OneToNMock {
    std::random_device rd;
    std::mt19937 _gen{rd()};
    std::uniform_int_distribution<> _dis;
    std::uniform_int_distribution<> _disVector{0, 500};
    std::uniform_int_distribution<> _disChar{0, 255};
    std::vector<ClientAdapter> _clients;
    Server _server;

   public:
    OneToNMock() = default;

    OneToNMock(size_t clientCount) : _dis(0, clientCount - 1) {
        setupServer();
        _clients = generateClients(clientCount);
    }

    void setupServer() {
        _server.setTransmissionManager(std::make_unique<ServerFiles>(&_server));
    }

    std::vector<ClientAdapter> generateClients(size_t num) {
        std::vector<ClientAdapter> clients;
        while (num--) {
            std::string name = "client" + std::to_string(num);
            clients.emplace_back(name);
        }

        return clients;
    }

    void registerAllClients() {
        for (auto &client : _clients) {
            client.createAccount();
        }
    }

    Client &send(const std::vector<unsigned char> &data) {
        int x = _dis(_gen);
        int y;
        do
            y = _dis(_gen);
        while (y == x);
        Client &receiver = *_clients[x].client;
        Client &sender = *_clients[y].client;

        std::cout << sender.getId() << " -> " << receiver.getId() << "; ";
        sender.sendData(receiver.getId(), data);

        return receiver;
    }

    std::vector<unsigned char> randomData() {
        auto gen = [&]() { return _disChar(_gen); };
        std::vector<unsigned char> vec(_disVector(_gen));
        std::generate(std::begin(vec), std::end(vec), gen);

        return vec;
    }

    ~OneToNMock() {
        ClientCleaner_Run();
        _server.dropDatabase();
    }
};

TEST_CASE("1-to-N messaging") {
    Network::setEnabled(true);
    Network::setProblematic(false);

    SECTION("random messages, all online") {
        OneToNMock mock(5);
        mock.registerAllClients();

        for (int i = 0; i < 1000; i++) {
            auto data = mock.randomData();
            auto &receiver = mock.send(data);
            CHECK(!receiver.getMessage().from.empty());
            CHECK(receiver.getMessage().data == data);
            receiver.getMessage().from = "";
        }
    }
}
