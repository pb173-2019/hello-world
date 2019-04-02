#include <utility>

#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/shared/requests.h"
#include "../../src/shared/responses.h"
#include "../../src/server/server.h"
#include "../../src/client/transmission_file_client.h"
#include "../../src/shared/connection_manager.h"

using namespace helloworld;

Request registerUser(const std::string &name, const std::string& sessionKey, const std::string& pubKeyFilename) {
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(name, key);
    return {{Request::Type::CREATE, 1, 0}, registerRequest.serialize()};
}

Request loginUser(const std::string &name, const std::string& sessionKey) {

    AuthenticateRequest auth(name, {});
    return {{Request::Type::LOGIN, 1, 0}, auth.serialize()};
}

Request completeAuth(const std::vector<unsigned char>& secret,
        const std::string &name,
        const std::string &privKeyFilename,
        const std::string &pwd,
        Request::Type type) {

    RSA2048 rsa;
    rsa.loadPrivateKey(privKeyFilename, pwd);

    CompleteAuthRequest crRequest(std::move(rsa.sign(secret)), name);
    return {{type, 2, 0}, crRequest.serialize()};
}

Request logoutUser(const std::string& username) {
    //id ignored for now, we run on names to simplify
    GenericRequest logout{0, username};
    return {{Request::Type::LOGOUT, 0, 0}, logout.serialize()};
}

Request deleteUser(const std::string& username) {
    //id ignored for now, we run on names to simplify
    GenericRequest logout{0, username};
    return {{Request::Type::REMOVE, 0, 0}, logout.serialize()};
}

class ClientMock : public Callable<void, std::stringstream &&> {

public:
    explicit ClientMock(std::string name) : _username(std::move(name)) {
        _transmission = std::make_unique<ClientFiles>(this, _username);
    }

    void callback(std::stringstream &&data) override {
        Response response = _connection->parseIncoming(std::move(data));
        switch (response.header.type) {
            case Response::Type::OK:
                CHECK(true);
                return;
            case Response::Type::KEY_BUNDLE_UPDATED: {
                CHECK(true);
                return;
            }
            case Response::Type::DATABASE_USERLIST: {
                UserListReponse data = UserListReponse::deserialize(response.payload);
                CHECK(data.online.size() == 3);
                std::string names{"alicebobcyril"};
                CHECK(names.find(data.online[1]) != std::string::npos);
                return;
            }
            case Response::Type::KEY_INIT_NEEDED: {

                if (!registered) registered = true;
                CHECK(true);
                std::stringstream buffer = _connection->parseOutgoing({{Request::Type::KEY_BUNDLE_UPDATE, 0, 0}, {0}});
                _transmission->send(buffer);
                return;
            }
            case Response::Type::CHALLENGE_RESPONSE_NEEDED: {
                Request complete = completeAuth(response.payload, _username,
                        "alice_priv.pem", "the most secure pwd ever",
                        (registered) ?  Request::Type::LOGIN_COMPLETE : Request::Type::CREATE_COMPLETE);
                std::stringstream buffer = _connection->parseOutgoing(complete);

                _transmission->send(buffer);
                return;
            }
            default: {
                throw std::runtime_error("Test failed: should not return such reponse.");
            }
        }
    }

    std::string _username = "alice";
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::unique_ptr<ClientToServerManager> _connection = nullptr;
    bool registered = false;
};

TEST_CASE("Create keys") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "the most secure pwd ever");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Scenario 1: create, logout, login, delete server") {

    Server server;

    ClientMock client{"alice"};
    client._connection = std::make_unique<ClientToServerManager>("2b7e151628aed2a6abf7158809cf4f3c", "server_pub.pem");


    std::stringstream registration = client._connection->parseOutgoing(
            registerUser("alice", "2b7e151628aed2a6abf7158809cf4f3c", "alice_pub.pem"));
    std::cout << "I am blue" << std::endl;

    //!! now when parsed, can set secure channel
    client._connection->switchSecureChannel(true);

    client._transmission->send(registration);
    //server receives request
    server.getRequest();
    //client receives challenge
    client._transmission->receive();
    //server verifies challenge and requests keys
    server.getRequest();
    //client sends keybundle
    client._transmission->receive();
    // server updates keys in database
    server.getRequest();
    // user recieves final OK response
    client._transmission->receive();
    std::cout << "I am blue" << std::endl;

    //reset connection
    std::stringstream loggingout = client._connection->parseOutgoing(logoutUser("alice"));
    client._transmission->send(loggingout);
    //server receives request
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();

    client._connection->switchSecureChannel(false);
    std::stringstream loggingin = client._connection->parseOutgoing(
            loginUser("alice", "2b7e151628aed2a6abf7158809cf4f3c"));
    client._connection->switchSecureChannel(true);
    std::cout << "I am blue" << std::endl;

    //!! now when parsed, can set secure channel
    client._transmission->send(loggingin);

    std::cout << "I am red" << std::endl;
    //server receives request
    server.getRequest();
    std::cout << "I am red" << std::endl;
    //client receives challenge
    client._transmission->receive();
    //server verifies challenge
    server.getRequest();
    std::cout << "I am red" << std::endl;
//client obtains the final OK response
    client._transmission->receive();
    std::cout << "I am blue" << std::endl;

    std::stringstream deleteuser = client._connection->parseOutgoing(deleteUser("alice"));
    client._transmission->send(deleteuser);
    //server receives request
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();
    server.dropDatabase();
    std::cout << "I am blue" << std::endl;

}

void registerUserRoutine(Server& server, ClientMock& client) {
    client._connection = std::make_unique<ClientToServerManager>("2b7e151628aed2a6abf7158809cf4f3c", "server_pub.pem");
    std::stringstream registration = client._connection->parseOutgoing(
            registerUser(client._username, "2b7e151628aed2a6abf7158809cf4f3c", "alice_pub.pem"));
    //!! now when parsed, can set secure channel
    client._connection->switchSecureChannel(true);
    client._transmission->send(registration);
    //server receives request
    server.getRequest();
    //client receives challenge
    client._transmission->receive();
    //server verifies challenge
    server.getRequest();
    //client obtains key init request
    client._transmission->receive();
    // server recieves keys
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();
}

TEST_CASE("Scenario 2: get online users.") {

    Server server;
    std::cout << "I am blue" << std::endl;

    ClientMock client1{"alice"};
    ClientMock client2{"bob"};
    ClientMock client3{"cyril"};
    std::cout << "I am blue" << std::endl;

    registerUserRoutine(server, client1);
    std::cout << "I am blue" << std::endl;

    registerUserRoutine(server, client2);
    registerUserRoutine(server, client3);
    std::cout << "I am blue" << std::endl;

    std::stringstream getOnline = client2._connection->parseOutgoing(
            {{Request::Type::GET_ONLINE, 0, 0}, GenericRequest{0, "bob"}.serialize()});
    client2._transmission->send(getOnline);
    std::cout << "I am blue" << std::endl;

    //server receives request
    server.getRequest();
    //client obtains the final OK response
    client2._transmission->receive();
    server.dropDatabase();
}
