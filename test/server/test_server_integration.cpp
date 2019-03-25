#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/server/requests.h"
#include "../../src/server/server.h"
#include "../../src/client/transmission_file_client.h"
#include "../../src/shared/connection_manager.h"

using namespace helloworld;

Request registerUser(const std::string &name, const std::string& sessionKey, const std::string& pubKeyFilename) {
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    RegisterRequest registerRequest(name, sessionKey, key);
    return {{Request::Type::CREATE, 1, 0}, registerRequest.serialize()};
}

Request loginUser(const std::string &name, const std::string& sessionKey) {

    AuthenticateRequest auth(name, sessionKey);
    return {{Request::Type::LOGIN, 1, 0}, auth.serialize()};
}

Request completeAuth(const std::vector<unsigned char>& secret,
        const std::string &name,
        const std::string &privKeyFilename,
        const std::string &pwd,
        Request::Type type) {

    RSA2048 rsa;
    rsa.loadPrivateKey(privKeyFilename, pwd);

    CompleteAuthRequest crRequest(std::move(rsa.decrypt(secret)), name);
    return {{type, 2, 0}, crRequest.serialize()};
}

Request logoutUser(const std::string& username) {
    //id ignored for now, we run on names to simplify
    NameIdNeededRequest logout{0, username};
    return {{Request::Type::LOGOUT, 0, 0}, logout.serialize()};
}

Request deleteUser(const std::string& username) {
    //id ignored for now, we run on names to simplify
    NameIdNeededRequest logout{0, username};
    return {{Request::Type::REMOVE, 0, 0}, logout.serialize()};
}

class ClientMock : public Callable<void, std::stringstream &&> {

public:
    ClientMock() {
        _transmission = std::make_unique<ClientFiles>(this, _username);
    }

    void callback(std::stringstream &&data) override {
        Response response = _connection->parseIncoming(std::move(data));
        switch (response.header.type) {
            case Response::Type::OK:
                return;
            case Response::Type::CHALLENGE_RESPONSE_NEEDED:
                Request complete = completeAuth(response.payload, _username,
                        "alice_priv.pem", "the most secure pwd ever", Request::Type::CREATE_COMPLETE);
                std::stringstream buffer = _connection->parseOutgoing(complete);
                _transmission->send(buffer);
                return;
        }
        throw std::runtime_error("test failed");
    }

    std::string _username = "alice";
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::unique_ptr<ClientToServerManager> _connection = nullptr;
};

TEST_CASE("Create key for alice") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "the most secure pwd ever");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Scenario 1: create, logout, login, delete.") {

    Server server;

    ClientMock client;
    client._connection = std::make_unique<ClientToServerManager>("server_pub.pem");

    std::stringstream registration = client._connection->parseOutgoing(
            registerUser("alice", "2b7e151628aed2a6abf7158809cf4f3c", "alice_pub.pem"));
    client._transmission->send(registration);
    //server receives request
    server.getRequest();
    //client receives challenge
    client._transmission->receive();
    //server verifies challenge
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();

    std::stringstream loggingout = client._connection->parseOutgoing(logoutUser("alice"));
    client._transmission->send(loggingout);
    //server receives request
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();

    std::stringstream loggingin = client._connection->parseOutgoing(
            loginUser("alice", "2b7e151628aed2a6abf7158809cf4f3c"));
    client._transmission->send(loggingin);
    //server receives request
    server.getRequest();
    //client receives challenge
    client._transmission->receive();
    //server verifies challenge
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();

    std::stringstream deleteuser = client._connection->parseOutgoing(deleteUser("alice"));
    client._transmission->send(deleteuser);
    //server receives request
    server.getRequest();
    //client obtains the final OK response
    client._transmission->receive();

}
