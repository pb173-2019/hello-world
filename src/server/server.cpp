#include <utility>

#include "server.h"
#include "sqlite_database.h"

#include "../shared/serializable_error.h"
#include "../shared/requests.h"
#include "../shared/responses.h"
#include "../shared/curve_25519.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<ServerSQLite>("test_db1")),
                   _genericManager("server_priv.pem",
                                   "323994cfb9da285a5d9642e1759b224a",
                                   "2b7e151628aed2a6abf7158809cf4f3c") {}

Response Server::handleUserRequest(const Request &request) {
    switch (request.header.type) {
        case Request::Type::CREATE:
            return registerUser(request);
        case Request::Type::CREATE_COMPLETE:
            return completeAuthentication(request);
        case Request::Type::LOGIN:
            return authenticateUser(request);
        case Request::Type::LOGIN_COMPLETE:
            return completeAuthentication(request); // changed
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
        case Request::Type::GET_RECEIVERS_BUNDLE:
            return sendKeyBundle(request);
        case Request::Type::CHECK_INCOMING:
            return checkIncoming(request);
        default:
            throw Error("Invalid operation.");
    }
}

Response Server::registerUser(const Request &request) {
    AuthenticateRequest registerRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, "", registerRequest.publicKey);
    if (!_database->select(userData).name.empty()) {
        throw Error("User " + userData.name + " is already registered.");
    }

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);

    {
        QWriteLocker lock(&_requestLock);
        bool inserted = _requestsToConnect.emplace(userData.name,
            std::make_pair(std::make_unique<Challenge>(userData, challengeBytes, registerRequest.sessionKey),
                    true)).second;
        if (!inserted)
            throw Error("User " + userData.name + " is already in the process of verification.");
    }

    log("Registration: " + registerRequest.name);
    _transmission->registerConnection(registerRequest.name);

    Response r = {Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.userId, challengeBytes};
    sendReponse(registerRequest.name, r, getManagerPtr(registerRequest.name, false));
    return r;
}

// Changed
Response Server::completeAuthentication(const Request &request) {
    CompleteAuthRequest curRequest =
            CompleteAuthRequest::deserialize(request.payload);

    QReadLocker lock(&_requestLock);
    auto authentication = _requestsToConnect.find(curRequest.name);
    if (authentication == _requestsToConnect.end()) {
        throw Error("No pending registration for provided username.");
    }


    RSA2048 rsa;
    uint32_t userId = 0;
    if (!authentication->second.second) {
        UserData user{0, curRequest.name, "", {}};
        UserData result = _database->select(user);
        userId = result.id;
        if (result.name.empty()) {
            throw Error("User with given name is not registered.");
        }
        rsa.setPublicKey(result.publicKey);

    } else {
        rsa.setPublicKey(authentication->second.first->userData.publicKey);
    }

    if (!rsa.verify(curRequest.secret, authentication->second.first->secret)) {
        throw Error("Cannot verify public key owner.");
    }

    QWriteLocker lock2(&_connectionLock);
    bool emplaced = _connections.emplace(curRequest.name, std::move(authentication->second.first->manager)).second;
    lock2.unlock();
    if (!emplaced)
        throw Error("Invalid authentication under an online account.");


    if (authentication->second.second) userId = _database->insert(authentication->second.first->userData, true);

    bool authenticationExists = authentication->second.second;
    lock.unlock();
    QWriteLocker lock3(&_requestLock); //todo better lock.lockForWrite(); ?
    _requestsToConnect.erase(curRequest.name);
    lock3.unlock();                    //lock.unlock();

    Response r = authenticationExists ?
            Response{Response::Type::USER_REGISTERED, userId} : checkEvent(request);

    log("Authentification succes: " + curRequest.name);
    r.header.userId = userId;
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::authenticateUser(const Request &request) {
    AuthenticateRequest authenticateRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, "", {});
    UserData result = _database->select(userData);

    if (result.name.empty())
        throw Error("User with given name is not registered.");

    QReadLocker lock(&_connectionLock);
    if (_connections.find(authenticateRequest.name) != _connections.end())
        throw Error("User is online.");
    lock.unlock();

    std::vector<unsigned char> challengeBytes = _random.get(CHALLENGE_SECRET_LENGTH);

    QWriteLocker lock2(&_requestLock);
    bool inserted = _requestsToConnect.emplace(authenticateRequest.name,
            std::make_pair(
                    std::make_unique<Challenge>(userData, challengeBytes,
                    authenticateRequest.sessionKey),
                    false)).second;
    lock2.unlock();
    if (!inserted) {
        throw Error("User with given name is already in the process of verification.");
    }
    _transmission->registerConnection(authenticateRequest.name);
    log("Log in: " + authenticateRequest.name);

    Response r = {Response::Type::CHALLENGE_RESPONSE_NEEDED, request.header.userId, challengeBytes};
    sendReponse(authenticateRequest.name, r, getManagerPtr(authenticateRequest.name, false));
    return r;
}

Response Server::getOnline(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    log("Get online: " + curRequest.name);

    const std::set<std::string> &users = _transmission->getOpenConnections();
    std::vector<uint32_t> ids;
    for (const auto& user : users) {
        UserData data = _database->select(user);
        ids.push_back(data.id);
    }

    Response r = {Response::Type::USERLIST, request.header.userId,
                  UserListReponse{{users.begin(), users.end()}, ids}.serialize()};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));

    return r;
}

Response Server::checkIncoming(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    log("Check incoming: " + curRequest.name);

    Response r = checkEvent(request);
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
        r = {Response::Type::FAILED_TO_DELETE_USER, request.header.userId};
    } else {
        _database->removeBundle(curRequest.id);
        _database->deleteAllData(curRequest.id);
        r = {Response::Type::OK, 0};
    }
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    logout(curRequest.name);
    log("Deleting account: " + curRequest.name);

    return r;
}

Response Server::logOut(const Request &request) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    Response r {Response::Type::OK, request.header.userId};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    logout(curRequest.name);

    return r;
}

void Server::logout(const std::string &name) {
    QWriteLocker lock(&_connectionLock);
    size_t deleted = _connections.erase(name);
    if (deleted != 1) {
        throw Error("Attempt to close connection: connections closed: " +
                    std::to_string(deleted));
    }
    lock.unlock();
    _transmission->removeConnection(name);
    log("Logging out: " + name);
}

void Server::dropDatabase() { _database->drop(); }

std::vector<std::string> Server::getUsers(const std::string &query) {
    const auto &users = _database->selectLike({0, query, "", {}});
    std::vector <std::string> names{};
    for (const auto &user : users) {
        names.push_back(user->name);
    }
    return names;
}

Response Server::findUsers(const Request &request) {

    GetUsers curRequest = GetUsers::deserialize(request.payload);
    log("Find User: " + curRequest.name + " ( query : " + curRequest.query + ")");

    UserListReponse response;
    const auto &users = _database->selectLike({0, curRequest.query, "", {}});
    for (const auto &user : users) {
        response.online.push_back(user->name);
        response.ids.push_back(user->id);
    }
    Response r = {{Response::Type::USERLIST, request.header.userId}, response.serialize()};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::forward(const Request &request) {
    Response r = checkEvent(request);

    //get receiver's name from database
    std::string receiver = _database->select(request.header.userId).name;
    if (receiver.empty())
        throw Error("Invalid receiver.");
    const std::set<std::string> &users = _transmission->getOpenConnections();
    if (users.find(receiver) != users.end())  {
        //todo message id?
        r = {Response::Type::RECEIVE, request.header.userId, request.header.fromId, request.payload};
        sendReponse(receiver, r, getManagerPtr(receiver, true));
    } else {
        _database->insertData(request.header.userId, request.payload);
    }
    return r;
}

Response Server::sendKeyBundle(const Request &request) {
    //for file transmission manager to use it to sent it back
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);

    log("sendKeyBundle: " + curRequest.name);
    std::vector<unsigned char> bundle = _database->selectBundle(request.header.userId);
    if (bundle.empty())
        throw Error("Could not find bundle for user " + std::to_string(request.header.userId));

    KeyBundle<C25519> keys = KeyBundle<C25519>::deserialize(bundle);
    if (!keys.oneTimeKeys.empty())
        keys.oneTimeKeys.erase(keys.oneTimeKeys.end() - 1);

    if (keys.oneTimeKeys.empty())
        _database->updateBundle(request.header.userId, keys.serialize(), 1); //timestamp to 1 - update needed
    else
        _database->updateBundle(request.header.userId, keys.serialize());

    Response r{Response::Type::RECEIVER_BUNDLE_SENT, request.header.userId, bundle};
    sendReponse(curRequest.name, r, getManagerPtr(curRequest.name, true));
    return r;
}

Response Server::checkEvent(const Request& request) {
    log("checking events");

    if (request.header.userId != 0) {
        // step one: old keys: if time stored + 2 weeks < now
        uint64_t time = _database->getBundleTimestamp(request.header.userId);
        if (time + 14*24*3600 < getTimestampOf(nullptr))
            return {Response::Type::BUNDLE_UPDATE_NEEDED, request.header.userId};

        // step two: one-time keys emptied //todo should be implemented or just wait for 2week period?
        KeyBundle<C25519> keys = KeyBundle<C25519>::deserialize(_database->selectBundle(request.header.userId));
        if (keys.oneTimeKeys.empty())
            return {Response::Type::BUNDLE_UPDATE_NEEDED, request.header.userId};

        // step three: new messages
        std::vector<unsigned char> msg = _database->selectData(request.header.userId);
        if (!msg.empty())
            return {Response::Type::RECEIVE_OLD, request.header.userId, std::move(msg)};
    }
    return {Response::Type::OK, request.header.userId};
}

ServerToClientManager *Server::getManagerPtr(const std::string &username, bool trusted) {
    ServerToClientManager *mngr = nullptr;
    if (trusted) {
        QReadLocker lock(&_connectionLock);
        auto found = _connections.find(username);
        if (found != _connections.end()) {
            mngr = &(*(found->second));
        }
    } else {
        QReadLocker lock(&_requestLock);
        auto found = _requestsToConnect.find(username);
        if (found != _requestsToConnect.end() && found->second.first->manager != nullptr) {
            mngr = &(*(found->second.first->manager));
        }
    }
    return mngr;
}

void Server::sendReponse(const std::string &username, const Response &response, ServerToClientManager *manager) {
    std::stringstream result;
    if (manager == nullptr) {
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

    Response r = {Response::Type::OK, request.header.userId};
    _database->insertBundle(request.header.userId, request.payload);

    //todo for file manager we need his username, but in future use ids only
    UserData user = _database->select(request.header.userId);
    log("Update keys: " + user.name);
    sendReponse(user.name, r, getManagerPtr(user.name, true));
    return r;
    }
}    // namespace helloworld
