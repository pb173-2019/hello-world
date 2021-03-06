
#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/client/transmission_file_client.h"
#include "../../src/server/server.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/connection_manager.h"
#include "../../src/shared/requests.h"
#include "../../src/shared/responses.h"

using namespace helloworld;

Request registerUser(const std::string &name,
                     const std::string &pubKeyFilename) {
    std::ifstream input(pubKeyFilename);
    zero::str_t publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    zero::bytes_t key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(name, key);
    return {{Request::Type::CREATE, 0}, registerRequest.serialize()};
}

Request loginUser(const std::string &name) {
    AuthenticateRequest auth(name, {});
    return {{Request::Type::LOGIN, 0}, auth.serialize()};
}

Request completeAuth(const std::vector<unsigned char> &secret,
                     const std::string &name,
                     const std::string &privKeyFilename, const zero::str_t &pwd,
                     Request::Type type) {
    RSA2048 rsa;
    rsa.loadPrivateKey(privKeyFilename, pwd);

    CompleteAuthRequest crRequest(std::move(rsa.sign(secret)), name);
    return {{type, 0}, crRequest.serialize()};
}

Request logoutUser(uint32_t id) { return {{Request::Type::LOGOUT, id}, {}}; }

Request deleteUser(uint32_t id) {
    GenericRequest deleteUser{id};
    return {{Request::Type::REMOVE, id}, deleteUser.serialize()};
}

struct ClientMock : public Callable<void, std::stringstream &&> {
    explicit ClientMock(std::string name) : _username(std::move(name)) {
        _transmission = std::make_unique<ClientFiles>(this, _username);
    }

    void callback(std::stringstream &&data) override {
        Response response = _connection->parseIncoming(std::move(data));
        switch (response.header.type) {
            case Response::Type::OK:
                CHECK(true);
                return;
            case Response::Type::USERLIST: {
                UserListReponse data =
                    UserListReponse::deserialize(response.payload);
                CHECK(data.online.size() == 3);
                std::string names{"alicebobcyril"};
                CHECK(names.find(data.online[1]) != std::string::npos);
                CHECK(names.find(data.online[2]) != std::string::npos);
                return;
            }
            case Response::Type::USER_REGISTERED: {
                registered = true;
                uid = response.header.userId;

                std::stringstream buffer = _connection->parseOutgoing(
                    {{Request::Type::KEY_BUNDLE_UPDATE, uid}, {0}});
                _transmission->send(buffer);
                return;
            }
            case Response::Type::BUNDLE_UPDATE_NEEDED: {
                std::stringstream buffer = _connection->parseOutgoing(
                    {{Request::Type::KEY_BUNDLE_UPDATE, uid}, {0}});
                _transmission->send(buffer);
                return;
            }
            case Response::Type::CHALLENGE_RESPONSE_NEEDED: {
                Request complete = completeAuth(
                    response.payload, _username, "alice_priv.pem",
                    "the most secure pwd ever", Request::Type::CHALLENGE);
                std::stringstream buffer = _connection->parseOutgoing(complete);

                _transmission->send(buffer);
                return;
            }
            default: {
                throw std::runtime_error(
                    "Test failed: should not return such reponse.");
            }
        }
    }

    MessageNumberGenerator counter;
    uint32_t uid = 0;
    std::string _username = "alice";
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::unique_ptr<ClientToServerManager> _connection = nullptr;
    bool registered = false;
};

TEST_CASE("Create keys") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "the most secure pwd ever");
    keygen.savePublicKey("alice_pub.pem");
    Server::setTest(true);
}

TEST_CASE("Scenario 1: create, logout, login, delete server") {
    Server server("Hello, world! 2.0 password");
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    ClientMock client{"alice"};
    client._connection = std::make_unique<ClientToServerManager>(
        "2b7e151628aed2a6abf7158809cf4f3c", "server_pub.pem");

    std::stringstream registration = client._connection->parseOutgoing(
        registerUser("alice", "alice_pub.pem"));

    //!! now when parsed, can set secure channel
    client._connection->switchSecureChannel(true);

    client._transmission->send(registration);
    // server receives request
    server.getRequest();
    // client receives challenge
    client._transmission->receive();
    // server verifies challenge and requests keys
    server.getRequest();
    // client sends keybundle
    client._transmission->receive();
    // server updates keys in database
    server.getRequest();
    // user recieves final OK response
    client._transmission->receive();

    // reset connection
    std::stringstream loggingout =
        client._connection->parseOutgoing(logoutUser(0));
    client._transmission->send(loggingout);
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client._transmission->receive();

    client._connection = std::make_unique<ClientToServerManager>(
        "2b7e151628aed2a6abf7158809cf4f3c", "server_pub.pem");

    std::stringstream loggingin =
        client._connection->parseOutgoing(loginUser("alice"));
    client._connection->switchSecureChannel(true);
    server.cleanAfterConenction("alice");

    //!! now when parsed, can set secure channel
    client._transmission->send(loggingin);

    // server receives request
    server.getRequest();
    // client receives challenge
    client._transmission->receive();
    // server verifies challenge
    server.getRequest();
    // client obtains the final OK response
    client._transmission->receive();

    std::stringstream deleteuser =
        client._connection->parseOutgoing(deleteUser(client.uid));
    client._transmission->send(deleteuser);
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client._transmission->receive();
    server.dropDatabase();
}

void registerUserRoutine(Server &server, ClientMock &client) {
    client._connection = std::make_unique<ClientToServerManager>(
        "2b7e151628aed2a6abf7158809cf4f3c", "server_pub.pem");
    std::stringstream registration = client._connection->parseOutgoing(
        registerUser(client._username, "alice_pub.pem"));

    //!! now when parsed, can set secure channel
    client._connection->switchSecureChannel(true);
    client._transmission->send(registration);
    // server receives request
    server.getRequest();
    // client receives challenge
    client._transmission->receive();
    // server verifies challenge
    server.getRequest();
    // client obtains key init request
    client._transmission->receive();
    // server recieves keys
    server.getRequest();
    // client obtains the final OK response
    client._transmission->receive();
}

TEST_CASE("Scenario 2: get online users.") {
    Server server("Hello, world! 2.0 password");
    server.setTransmissionManager(std::make_unique<ServerFiles>(&server));

    ClientMock client1{"alice"};
    ClientMock client2{"bob"};
    ClientMock client3{"cyril"};

    registerUserRoutine(server, client1);
    registerUserRoutine(server, client2);
    registerUserRoutine(server, client3);

    std::stringstream getOnline = client2._connection->parseOutgoing(
        {{Request::Type::GET_ONLINE, 0}, GenericRequest{0}.serialize()});
    client2._transmission->send(getOnline);

    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client2._transmission->receive();
    server.dropDatabase();
}
