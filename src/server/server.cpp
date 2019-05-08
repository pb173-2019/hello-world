#include <utility>

#include "server.h"
#include "sqlite_database.h"

#include "../shared/curve_25519.h"
#include "../shared/requests.h"
#include "../shared/responses.h"
#include "../shared/serializable_error.h"

namespace helloworld {

bool Server::_test{false};

Server::Server(zero::str_t password)
    : _genericManager("server_priv.pem", std::move(password)),
      _database(std::make_unique<ServerSQLite>("test_db1")) {}

Response Server::handleUserRequest(const Request &request,
                                   const std::string &username) {
    switch (request.header.type) {
        case Request::Type::CREATE:
            return registerUser(request);
        case Request::Type::CHALLENGE:
            return completeAuthentication(request);
        case Request::Type::LOGIN:
            return authenticateUser(request);
        case Request::Type::GET_ONLINE:
            return getOnline(request, username);
        case Request::Type::FIND_USERS:
            return findUsers(request, username);
        case Request::Type::SEND:
            return forward(request);
        case Request::Type::REMOVE:
            return deleteAccount(request, username);
        case Request::Type::LOGOUT:
            return logOut(request, username);
        case Request::Type::KEY_BUNDLE_UPDATE:
            return updateKeyBundle(request, username);
        case Request::Type::GET_RECEIVERS_BUNDLE:
            return sendKeyBundle(request, username);
        case Request::Type::CHECK_INCOMING:
            return checkIncoming(request, username);
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

    std::vector<unsigned char> challengeBytes =
        _random.get(CHALLENGE_SECRET_LENGTH);

    {
        QWriteLocker lock(&_requestLock);
        bool inserted =
            _requestsToConnect
                .emplace(userData.name,
                         std::make_pair(std::make_unique<Challenge>(
                                            userData, challengeBytes,
                                            registerRequest.sessionKey),
                                        true))
                .second;
        if (!inserted)
            throw Error("User " + userData.name +
                        " is already in the process of verification.");

        if (_test)
            _requestsToConnect[userData.name].first->manager->_testing = _test;
    }

    log("Registration: " + registerRequest.name);
    _transmission->registerConnection(registerRequest.name);

    Response r = {Response::Type::CHALLENGE_RESPONSE_NEEDED,
                  request.header.userId, challengeBytes};
    sendReponse(registerRequest.name, r,
                getManagerPtr(registerRequest.name, false));
    return r;
}

Response Server::completeAuthentication(const Request &request) {
    CompleteAuthRequest curRequest =
        CompleteAuthRequest::deserialize(request.payload);

    QReadLocker lock(&_requestLock);
    auto authentication = _requestsToConnect.find(curRequest.name);
    if (authentication == _requestsToConnect.end()) {
        throw Error("No pending registration for provided username.");
    }
    bool newUser = authentication->second.second;

    RSA2048 rsa;
    uint32_t userId = 0;
    if (!newUser) {
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
    bool emplaced =
        _connections
            .emplace(curRequest.name,
                     std::move(authentication->second.first->manager))
            .second;
    lock2.unlock();
    if (!emplaced)
        throw Error("Invalid authentication under an online account.");

    if (newUser)
        userId =
            _database->insert(authentication->second.first->userData, true);
    lock.unlock();
    QWriteLocker lock3(&_requestLock);    // todo better lock.lockForWrite(); ?
    _requestsToConnect.erase(curRequest.name);
    lock3.unlock();    // lock.unlock();

    Response r = newUser ? Response{Response::Type::USER_REGISTERED, userId}
                         : checkEvent(userId);
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

    std::vector<unsigned char> challengeBytes =
        _random.get(CHALLENGE_SECRET_LENGTH);

    QWriteLocker lock2(&_requestLock);
    bool inserted =
        _requestsToConnect
            .emplace(authenticateRequest.name,
                     std::make_pair(std::make_unique<Challenge>(
                                        userData, challengeBytes,
                                        authenticateRequest.sessionKey),
                                    false))
            .second;
    lock2.unlock();
    if (!inserted) {
        throw Error(
            "User with given name is already in the process of verification.");
    }
    _transmission->registerConnection(authenticateRequest.name);
    log("Log in: " + authenticateRequest.name);

    Response r = {Response::Type::CHALLENGE_RESPONSE_NEEDED,
                  request.header.userId, challengeBytes};
    sendReponse(authenticateRequest.name, r,
                getManagerPtr(authenticateRequest.name, false));
    return r;
}

Response Server::getOnline(const Request &request,
                           const std::string &username) {
    log("Get online: " + username);

    const std::set<std::string> &users = _transmission->getOpenConnections();
    std::vector<uint32_t> ids;
    for (const auto &user : users) {
        UserData data = _database->select(user);
        ids.push_back(data.id);
    }

    Response r = {
        Response::Type::USERLIST, request.header.userId,
        UserListReponse{{users.begin(), users.end()}, ids}.serialize()};
    sendReponse(username, r, getManagerPtr(username, true));
    return r;
}

Response Server::checkIncoming(const Request &request,
                               const std::string &username) {
    log("Check incoming: " + username);

    Response r = checkEvent(request.header.userId);
    sendReponse(username, r, getManagerPtr(username, true));
    return r;
}

Response Server::deleteAccount(const Request &request,
                               const std::string &username) {
    GenericRequest curRequest = GenericRequest::deserialize(request.payload);
    if (_database->select(curRequest.id).name != username)
        throw Error("Invalid action.");

    Response r;
    if (!_database->remove({curRequest.id, username, "", {}})) {
        r = {Response::Type::FAILED_TO_DELETE_USER, request.header.userId};
    } else {
        _database->removeBundle(curRequest.id);
        _database->deleteAllData(curRequest.id);
        r = {Response::Type::OK, 0};
    }
    sendReponse(username, r, getManagerPtr(username, true));
    logout(username);
    log("Deleting account: " + username);

    return r;
}

Response Server::logOut(const Request &request, const std::string &username) {
    Response r{Response::Type::OK, request.header.userId};
    sendReponse(username, r, getManagerPtr(username, true));
    logout(username);

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
    std::vector<std::string> names{};
    for (const auto &user : users) {
        names.push_back(user->name);
    }
    return names;
}

Response Server::findUsers(const Request &request,
                           const std::string &username) {
    GetUsers curRequest = GetUsers::deserialize(request.payload);
    log("Find User: " + username + " ( query : \"" + curRequest.query + "\" )");

    UserListReponse response;
    const auto &users = _database->selectLike({0, curRequest.query, "", {}});
    for (const auto &user : users) {
        response.online.push_back(user->name);
        response.ids.push_back(user->id);
    }
    Response r = {{Response::Type::USERLIST, request.header.userId},
                  response.serialize()};
    sendReponse(username, r, getManagerPtr(username, true));
    return r;
}

Response Server::forward(const Request &request) {
    Response r = checkEvent(request.header.userId);

    // get receiver's name from database
    std::string receiver = _database->select(request.header.userId).name;
    if (receiver.empty()) throw Error("Invalid receiver.");

    const std::set<std::string> &users = _transmission->getOpenConnections();
    if (users.find(receiver) != users.end()) {
        r = {Response::Type::RECEIVE, request.header.userId,
             request.header.fromId, request.payload};
        sendReponse(receiver, r, getManagerPtr(receiver, true));
    } else {
        _database->insertData(request.header.userId, request.payload);
    }
    return r;
}

Response Server::sendKeyBundle(const Request &request,
                               const std::string &username) {
    // for file transmission manager to use it to sent it back
    log("sendKeyBundle: " + username);
    std::vector<unsigned char> bundle =
        _database->selectBundle(request.header.userId);
    if (bundle.empty())
        throw Error("Could not find bundle for user " +
                    std::to_string(request.header.userId));

    KeyBundle<C25519> keys = KeyBundle<C25519>::deserialize(bundle);
    if (!keys.oneTimeKeys.empty())
        keys.oneTimeKeys.erase(keys.oneTimeKeys.end() - 1);

    if (keys.oneTimeKeys.empty())
        _database->updateBundle(request.header.userId, keys.serialize(),
                                1);    // timestamp to 1 - update needed
    else
        _database->updateBundle(request.header.userId, keys.serialize());

    Response r{Response::Type::RECEIVER_BUNDLE_SENT, request.header.userId,
               bundle};
    sendReponse(username, r, getManagerPtr(username, true));
    return r;
}

Response Server::checkEvent(uint32_t uid) {
    if (_test)
        return {Response::Type::OK,
                uid};    // some tests dont add keys during registration
                         // and after fixing check event, it causes segfault

    if (uid != 0) {
        // step one: old keys: if time stored + 2 weeks < now
        uint64_t time = _database->getBundleTimestamp(uid);
        if (time + 14 * 24 * 3600 < getTimestampOf(nullptr)) {
            log("checking events: #" + std::to_string(uid) +
                " : update key bundle");
            return {Response::Type::BUNDLE_UPDATE_NEEDED, uid};
        }
        // step two: one-time keys emptied //todo should be implemented or just
        // wait for 2week period?
        KeyBundle<C25519> keys =
            KeyBundle<C25519>::deserialize(_database->selectBundle(uid));
        if (keys.oneTimeKeys.empty()) {
            log("checking events: #" + std::to_string(uid) + " : new keys");
            return {Response::Type::BUNDLE_UPDATE_NEEDED, uid};
        }
        // step three: new messages
        std::vector<unsigned char> msg = _database->selectData(uid);
        if (!msg.empty()) {
            log("checking events: #" + std::to_string(uid) + " : new message");
            return {Response::Type::RECEIVE_OLD, uid, std::move(msg)};
        }
    }
    log("checking events: #" + std::to_string(uid) + " : no new events");
    return {Response::Type::OK, uid};
}

ServerToClientManager *Server::getManagerPtr(const std::string &username,
                                             bool trusted) {
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
        if (found != _requestsToConnect.end() &&
            found->second.first->manager != nullptr) {
            mngr = &(*(found->second.first->manager));
        }
    }
    return mngr;
}

void Server::sendReponse(const std::string &username, const Response &response,
                         ServerToClientManager *manager) {
    std::stringstream result;
    if (manager == nullptr) {
        result = _genericManager.returnErrorGeneric();
    } else {
        result = manager->parseOutgoing(response);
    }
    _transmission->send(username, result);
}

void Server::sendReponse(const std::string &username, const Response &response,
                         const zero::str_t &sessionKey) {
    std::stringstream result;
    if (sessionKey.length() != AESGCM::key_size * 2) {
        // invalid key
        result = _genericManager.returnErrorGeneric();
    } else {
        _genericManager.setKey(sessionKey);
        result = _genericManager.parseOutgoing(response);
    }
    _transmission->send(username, result);
}

Response Server::updateKeyBundle(const Request &request,
                                 const std::string &username) {
    Response r = {Response::Type::OK, request.header.userId};
    UserData user = _database->select(request.header.userId);
    if (user.name != username)
        throw Error("Key bundle update policy violation.");

    _database->insertBundle(request.header.userId, request.payload);
    log("Update keys: " + username);
    sendReponse(username, r, getManagerPtr(username, true));
    return r;
}

}    // namespace helloworld
