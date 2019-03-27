#include <utility>

#include "server.h"
#include "../shared/serializable_error.h"
#include "sqlite_database.h"
#include "requests.h"
#include "responses.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<ServerSQLite>("test_db1")),
                   _transmission(std::make_unique<ServerFiles>(this)),
                   _genericManager("server_priv.pem",
                                   "323994cfb9da285a5d9642e1759b224a",
                                   "2b7e151628aed2a6abf7158809cf4f3c") {}

Response Server::handleUserRequest(const Request &request) {
    switch (request.header.type) {
        case Request::Type::CREATE:
            return registerUser(request);
        case Request::Type::CREATE_COMPLETE:
            return completeAuthentication(request, true);
        case Request::Type::LOGIN:
            return authenticateUser(request);
        case Request::Type::LOGIN_COMPLETE:
            return completeAuthentication(request, false);
        case Request::Type::GET_ONLINE:
            return getOnline(request);
        case Request::Type::REMOVE:
            return deleteAccount(request);
        case Request::Type::LOGOUT:
            return logOut(request);
        default:
            throw Error("Invalid operation.");
    }
}

Response Server::registerUser(const Request &request) {
    RegisterRequest registerRequest =
            RegisterRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, "", registerRequest.publicKey);
    if (!_database->selectUsers(userData).empty()) {
        throw Error("User " + userData.name + " is already registered.");
    }

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);
    _transmission->registerConnection(registerRequest.name);
    bool inserted = _requestsToConnect.emplace(userData.name,
            std::make_unique<Challenge>(userData, challengeBytes, registerRequest.sessionKey)).second;

    if (!inserted) {
        throw Error("User " + userData.name + " is already in the process of verification.");
    }

    Response r = {{Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.messageNumber,
                   request.header.userId}, challengeBytes};
    sendReponse(registerRequest.name, r, getManagerPtr(registerRequest.name, false));
    return r;
}

Response Server::completeAuthentication(const Request &request, bool newUser) {
    CompleteAuthRequest curRequest =
            CompleteAuthRequest::deserialize(request.payload);

    auto registration = _requestsToConnect.find(curRequest.name);
    if (registration == _requestsToConnect.end()) {
        throw Error("No pending registration for provided username.");
    }

    RSA2048 rsa;

    if (! newUser) {
        UserData user{0, curRequest.name, "", {}};
        auto &resultList = _database->selectUsers(user);
        if (resultList.empty()) {
            throw Error("User with given name is not registered.");
        }
        for (auto &item : resultList) {
            if (item->name == curRequest.name) {
                rsa.setPublicKey(item->publicKey);
                break;
            }
        }
    } else {
        rsa.setPublicKey(registration->second->userData.publicKey);
    }

    if (! rsa.verify(curRequest.secret, registration->second->secret)) {
        throw Error("Cannot verify public key owner.");
    }

    if (newUser) _database->insert(registration->second->userData, true);
    _connections.emplace(curRequest.name, std::move(registration->second->manager));
    _requestsToConnect.erase(curRequest.name);

    Response r = {{Response::Type::OK, request.header.messageNumber, request.header.userId}, {}};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::authenticateUser(const Request &request) {
    AuthenticateRequest authenticateRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, "", {});
    auto &resultList = _database->selectUsers(userData);
    if (resultList.empty()) {
        throw Error("User with given name is not registered.");
    }
    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);
    //the secure channel is opened, but do not trusted, until not moved into connections vector
    _transmission->registerConnection(authenticateRequest.name);

    bool inserted = _requestsToConnect.emplace(authenticateRequest.name,
            std::make_unique<Challenge>(userData, challengeBytes, authenticateRequest.sessionKey)).second;
    if (!inserted) {
        throw Error("User with given name is already in the process of verification.");
    }

    Response r = {{Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.messageNumber,
                  request.header.userId}, challengeBytes};
    sendReponse(authenticateRequest.name, r, getManagerPtr(authenticateRequest.name, false));
    return r;
}

Response Server::getOnline(const Request &request) {
    NameIdNeededRequest curRequest = NameIdNeededRequest::deserialize(request.payload);

    const std::set<std::string> &users = _transmission->getOpenConnections();
    Response r = {{Response::Type::DATABASE_ONLINE_SEND, request.header.messageNumber, request.header.userId},
            OnlineUsersResponse{{users.begin(), users.end()}}.serialize()};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::deleteAccount(const Request &request) {
    NameIdNeededRequest curRequest =
            NameIdNeededRequest::deserialize(request.payload);
    UserData data;
    data.name = curRequest.name;
    data.id = curRequest.id;
    Response r;
    if (!_database->removeUser({curRequest.id, curRequest.name, "", {}})) {
        r = {{Response::Type::FAILED_TO_DELETE_USER, 0, 0}, {}};
    } else {
        r = {{Response::Type::OK, 0, 0}, {}};
    }
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    logout(curRequest.name);
    return r;
}

Response Server::logOut(const Request &request) {
    NameIdNeededRequest curRequest =
            NameIdNeededRequest::deserialize(request.payload);
    Response r = {{Response::Type::OK, 0, 0}, {}};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    logout(curRequest.name);
    return r;
}

void Server::logout(const std::string &name) {
    size_t deleted = _connections.erase(name);
    if (deleted != 1) {
        throw Error("Attempt to close connection: connections closed: " +
        std::to_string(deleted));
    }
    _transmission->removeConnection(name);
}

void Server::dropDatabase() { _database->drop(); }

std::vector<std::string> Server::getUsers() {
    const auto &users = _database->selectUsers({});
    std::vector<std::string> names;
    for (const auto &user : users) {
        names.push_back(user->name);
    }
    return names;
}

ServerToClientManager *Server::getManagerPtr(const std::string &username, bool trusted) {
    ServerToClientManager *mngr = nullptr;
    if (trusted) {
        auto found = _connections.find(username);
        if (found != _connections.end()) {
            mngr = &(*(found->second));
        }
    } else {
        auto found = _requestsToConnect.find(username);
        if (found != _requestsToConnect.end() && found->second->manager != nullptr) {
            mngr = &(*(found->second->manager));
        }
    }
    return mngr;
}

void Server::sendReponse(const std::string &username, const Response &response, ServerToClientManager *manager) {
    std::stringstream result;
    if (manager == nullptr) {
        //unable to get session to correctly encrypt reponse
        result = std::move(_genericManager.returnErrorGeneric());
    } else {
        result = std::move(manager->parseOutgoing(response));
    }
    _transmission->send(username, result);
}


void Server::sendReponse(const std::string &username, const Response &response, const std::string &sessionKey) {
    std::stringstream result;
    if (sessionKey.length() != AESGCM::key_size * 2) {
        //invalid key
        result = std::move(_genericManager.returnErrorGeneric());
    } else {
        result = std::move(_genericManager.parseErrorGCM(response, sessionKey));
    }
    _transmission->send(username, result);
}

}    // namespace helloworld
