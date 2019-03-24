#include <utility>

#include "server.h"
#include "../shared/serializable_error.h"
#include "file_database.h"
#include "requests.h"
#include "responses.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<FileDatabase>("test_db1.db")),
                   _transmission(std::make_unique<FileManager>(this)),
                   _genericManager("server_priv.pem",
                                   "323994cfb9da285a5d9642e1759b224a",
                                   "2b7e151628aed2a6abf7158809cf4f3c") {}

Response Server::handleUserRequest(const Request &request) {
    try {
        switch (request.header.type) {
            case Request::Type::CREATE:
                return registerUser(request);
            case Request::Type::CREATE_COMPLETE:
                return completeUserRegistration(request);
            case Request::Type::LOGIN:
                return authenticateUser(request);
            case Request::Type::LOGIN_COMPLETE:
                return completeUserAuthentication(request);
            case Request::Type::GET_ONLINE:
                return getOnline(request);
            default:
                throw Error("Invalid operation.");
        }
    } catch (Error &ex) {
        std::cerr << ex.what() << std::endl;
        return {{Response::Type::GENERIC_SERVER_ERROR, request.header.messageNumber, request.header.userId},
                ex.serialize()};
    }
}

//todo remove..?
uint32_t Server::establishConnection() {
    return 42;
}

//todo remove..?
void Server::terminateConnection(uint32_t cid) {

}

Response Server::registerUser(const Request &request) {
    RegisterRequest registerRequest =
            RegisterRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, "", registerRequest.publicKey);
    if (!_database->select(userData).empty()) {
        throw Error("User " + userData.name + " is already registered.");
    }

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);
    //the secure channel is opened, but do not trusted, until not moved into connections vector
    _transmission->registerConnection(registerRequest.name);
    bool inserted = _requestsToConnect.emplace(userData.name,
            std::make_unique<Challenge>(userData, challengeBytes, registerRequest.sessionKey)).second;
    if (!inserted) {
        throw Error("User " + userData.name + " is already in the process of verification.");
    }

    RSA2048 rsa;
    rsa.setPublicKey(registerRequest.publicKey);

    return {{Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.messageNumber, request.header.userId},
            rsa.encrypt(challengeBytes)};
}

Response Server::completeUserRegistration(const Request &request) {
    CompleteRegistrationRequest curRequest =
            CompleteRegistrationRequest::deserialize(request.payload);

    auto registration = _requestsToConnect.find(curRequest.name);
    if (registration == _requestsToConnect.end()) {
        throw Error("No pending registration for provided username.");
    }

    if (curRequest.secret != registration->second->secret) {
        throw Error("Cannot verify public key owner.");
    }

    _database->insert(registration->second->userData);
    _connections.emplace(curRequest.name, std::move(registration->second->manager));
    _requestsToConnect.erase(curRequest.name);

    return {{Response::Type::OK, request.header.messageNumber, request.header.userId}, {}};
}

Response Server::authenticateUser(const Request &request) {
    AuthenticateRequest authenticateRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, "", {});
    auto &resultList = _database->select(userData);
    if (resultList.empty()) {
        throw Error("User with given name is not registered.");
    }
    for (auto &item : resultList) {
        if (item->name == authenticateRequest.name) {
            userData.publicKey = item->publicKey;
            break;
        }
    }

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);
    //the secure channel is opened, but do not trusted, until not moved into connections vector
    _transmission->registerConnection(authenticateRequest.name);

    bool inserted = _requestsToConnect.emplace(authenticateRequest.name,
            std::make_unique<Challenge>(userData, challengeBytes, authenticateRequest.sessionKey)).second;
    if (!inserted) {
        throw Error("User with given name is already in the process of verification.");
    }

    RSA2048 rsa;
    rsa.setPublicKey(userData.publicKey);

    return {{Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.messageNumber, request.header.userId},
            rsa.encrypt(challengeBytes)};
}

Response Server::completeUserAuthentication(const Request &request) {
    CompleteRegistrationRequest curRequest =
            CompleteRegistrationRequest::deserialize(request.payload);

    auto authentication = _requestsToConnect.find(curRequest.name);
    if (authentication == _requestsToConnect.end()) {
        throw Error("No pending authentication for provided username.");
    }

    if (curRequest.secret != authentication->second->secret) {
        throw Error("Cannot verify public key owner.");
    }

    _connections.emplace(curRequest.name, std::move(authentication->second->manager));
    _requestsToConnect.erase(curRequest.name);
    return {{Response::Type::OK, request.header.messageNumber, request.header.userId}, {}};
}

Response Server::getOnline(const Request &request) {
    const std::set<std::string> &users = _transmission->getOpenConnections();
    return {{Response::Type::OK, request.header.messageNumber, request.header.userId},
            OnlineUsersResponse{{users.begin(), users.end()}}.serialize()};
}

void Server::dropDatabase() { _database->drop(); }

std::vector<std::string> Server::getUsers() {
    const auto &users = _database->select({});
    std::vector<std::string> names;
    for (const auto &user : users) {
        names.push_back(user->name);
    }

    return names;
}

}    // namespace helloworld
