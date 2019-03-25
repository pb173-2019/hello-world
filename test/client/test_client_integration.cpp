#include <utility>

#include <fstream>
#include "catch.hpp"

#include "../../src/client/client.h"
#include "../../src/server/transmission_file_server.h"
#include "../../src/shared/connection_manager.h"

#include "../../src/server/server.h"

using namespace helloworld;

//class ServerMock
//    : public Callable<void, bool, const std::string &, std::stringstream &&> {
//   public:
//    std::unique_ptr<ServerToClientManager> _connection;
//    ServerFiles _transmission{this};
//    GenericServerManager _genericManager{"server_priv.pem",
//                                         "323994cfb9da285a5d9642e1759b224a",
//                                         "2b7e151628aed2a6abf7158809cf4f3c"};
//
//    Response getResponse(helloworld::Request::Type type) {
//        switch (type) {
//            case Request::Type::CREATE:
//                _transmission.registerConnection("alice");
//                return {{Response::Type::CHALLENGE_RESPONSE_NEEDED, 1, 0}, {}};
//            case Request::Type::LOGIN:
//                _transmission.registerConnection("alice");
//                return {{Response::Type::CHALLENGE_RESPONSE_NEEDED, 1, 0}, {}};
//            case Request::Type::LOGOUT:
//            case Request::Type::REMOVE:
//                _transmission.removeConnection("alice");
//                return {{Response::Type::OK, 1, 0}, {}};
//            default:
//                return {{Response::Type::OK, 1, 0}, {}};
//        }
//    }
//
//    void callback(bool hasSessionKey, const std::string &username,
//                  std::stringstream &&data) override {
//        Request request;
//
//        if (!hasSessionKey) {
//            request = _genericManager.parseIncoming(std::move(data));
//            if (request.header.type == Request::Type::CREATE) {
//                RegisterRequest registerRequest =
//                    RegisterRequest::deserialize(request.payload);
//                _connection = std::make_unique<ServerToClientManager>(
//                    registerRequest.sessionKey);
//            }
//        } else {
//            request = _connection->parseIncoming(std::move(data));
//        }
//
//        auto response = getResponse(request.header.type);
//        auto result = _connection->parseOutgoing(response);
//        _transmission.send(username, result);
//    }
//
//    void getRequest() { _transmission.receive(); }
//};

TEST_CASE("Create key for alice") {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword("alice_priv.pem", "hunter2");
    keygen.savePublicKey("alice_pub.pem");
}

TEST_CASE("Scenario 1: create, logout, login, delete.") {
    Server server;

    Client client("alice", "server_pub.pem", "alice_priv.pem", "hunter2");
    client.createAccount("alice_pub.pem");

    std::cout << "server receives request\n";
    // server receives request
    server.getRequest();

    std::cout << "client receives challenge\n";
    // client receives challenge
    client.getRequest();

    std::cout << "server verifies challenge\n";
    // server verifies challenge
    server.getRequest();

    std::cout << "client obtains the final OK response\n";
    // client obtains the final OK response
    client.getRequest();

    client.logout();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();

    client.login();
    // server receives request
    server.getRequest();
    // client receives challenge
    client.getRequest();
    // server verifies challenge
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();

    client.deleteAccount();
    // server receives request
    server.getRequest();
    // client obtains the final OK response
    client.getRequest();
}
