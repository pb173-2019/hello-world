#include <utility>

#include "server.h"
#include "../shared/serializable_error.h"
#include "sqlite_database.h"
#include "../shared/requests.h"
#include "../shared/responses.h"

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
        case Request::Type::FIND_USERS:
            return findUsers(request);
        case Request::Type::SEND:
            return forward(request);
        case Request::Type::REMOVE:
            return deleteAccount(request);
        case Request::Type::LOGOUT:
            return logOut(request);
        case Request::Type::KEY_BUNDLE_UPDATE:
            return updateKeyBundle(request);
            default:
            throw Error("Invalid operation.");
    }
}

Response Server::registerUser(const Request &request) {
    AuthenticateRequest registerRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, "", registerRequest.publicKey);
    if (!_database->select(userData).empty()) {
        throw Error("User " + userData.name + " is already registered.");
    }

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);
    bool inserted = _requestsToConnect.emplace(userData.name,
            std::make_unique<Challenge>(userData, challengeBytes, registerRequest.sessionKey)).second;

    if (!inserted) {
        throw Error("User " + userData.name + " is already in the process of verification.");
    }
    _transmission->registerConnection(registerRequest.name);

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

    if (!newUser) {
        UserData user{0, curRequest.name, "", {}};
        auto &resultList = _database->select(user);
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

    if (!rsa.verify(curRequest.secret, registration->second->secret)) {
        throw Error("Cannot verify public key owner.");
    }

    bool emplaced = _connections.emplace(curRequest.name, std::move(registration->second->manager)).second;
    if (!emplaced)
        throw Error("Invalid authentication under an online account.");

    uint32_t generatedId = 0;
    if (newUser) generatedId = _database->insert(registration->second->userData, true);
    _requestsToConnect.erase(curRequest.name);

    Response r;
    if (newUser)
        r = {{Response::Type::BUNDLE_UPDATE_NEEDED, 0, generatedId},{}};
    else
        r = checkEvent(request);

    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));


    return r;
}

Response Server::authenticateUser(const Request &request) {
    AuthenticateRequest authenticateRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, "", {});
    auto &resultList = _database->select(userData);

    if (resultList.empty())
        throw Error("User with given name is not registered.");
    if (_connections.find(authenticateRequest.name) != _connections.end())
        throw Error("User is online.");

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);

    bool inserted = _requestsToConnect.emplace(authenticateRequest.name,
            std::make_unique<Challenge>(userData, challengeBytes,
                    authenticateRequest.sessionKey)).second;

    if (!inserted) {
        throw Error("User with given name is already in the process of verification.");
    }
    _transmission->registerConnection(authenticateRequest.name);


    Response r = {{Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.messageNumber,
                   request.header.userId}, challengeBytes};
    sendReponse(authenticateRequest.name, r, getManagerPtr(authenticateRequest.name, false));
    return r;
}

Response Server::getOnline(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);

    const std::set <std::string> &users = _transmission->getOpenConnections();
    Response r = {{Response::Type::USERLIST, request.header.messageNumber, request.header.userId},
                  UserListReponse{{users.begin(), users.end()}}.serialize()};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::deleteAccount(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    UserData data;
    data.name = curRequest.name;
    data.id = curRequest.id;
    Response r;
    if (!_database->remove({curRequest.id, curRequest.name, "", {}})) {
        r = {{Response::Type::FAILED_TO_DELETE_USER, request.header.messageNumber, request.header.userId}, {}};
    } else {
        r = checkEvent(request);
    }
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    logout(curRequest.name);
    return r;
}

Response Server::logOut(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    Response r = checkEvent(request);
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

std::vector <std::string> Server::getUsers(const std::string &query) {
    const auto &users = _database->selectLike({0, query, "", {}});
    std::vector <std::string> names{};
    for (const auto &user : users) {
        names.push_back(user->name);
    }
    return names;
}

Response Server::findUsers(const Request &request) {
    GetUsers curRequest = GetUsers::deserialize(request.payload);
    UserListReponse response;
    response.online = getUsers(curRequest.query);
    Response r = {{Response::Type::USERLIST, 0, 0}, response.serialize()};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::forward(const Request &request) {
    Response r = checkEvent(request);

    //get receiver's name from database
    std::string receiver = (_database->select({request.header.userId, "", "", {}}))[0]->name;
    const std::set<std::string> &users = _transmission->getOpenConnections();
    if (users.find(receiver) != users.end())  {
        //todo message id?
        r = {{Response::Type::RECEIVE, 0, request.header.userId}, request.payload};
        sendReponse(receiver, r, getManagerPtr(receiver, true));
    } else {
        _database->insertData(request.header.userId, request.payload);
    }
    return r;
}


Response Server::checkEvent(const Request& request) {
    //todo check for keys that should be updated
    //todo check for new messages that are waiting for user to come online
    return {{Response::Type::OK, request.header.messageNumber, request.header.userId}, {}};
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
        _genericManager.setKey(sessionKey);
        result = std::move(_genericManager.parseOutgoing(response));
    }
    _transmission->send(username, result);
}

Response Server::updateKeyBundle(const Request &request) {
    Response r = {{Response::Type::KEY_BUNDLE_UPDATED, 0, request.header.userId}, {}};
    _database->insertBundle(request.header.userId, request.payload);

     return r;
    }

}    // namespace helloworld
