#include <utility>

#include "server.h"
#include "../shared/serializable_error.h"
#include "file_database.h"
#include "requests.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<FileDatabase>("test_db1.db")),
                   _transmission(std::make_unique<FileManager>(this)) {}

void Server::setSessionKey(const std::string &name, std::vector<unsigned char> sessionKey) {
    _connections[name].sessionKey = std::move(sessionKey);
}

Response Server::handleUserRequest(const Request &request) {
    try {
        switch (request.type) {
            case Request::Type::CREATE:
                return registerUser(request);
            case Request::Type::CREATE_COMPLETE:
                return completeUserRegistration(request);
            case Request::Type::LOGIN:
                return authenticateUser(request);
            case Request::Type::LOGIN_COMPLETE:
                return completeUserAuthentication(request);
            default:
                throw Error("Invalid operation.");
        }
    } catch (Error &ex) {
        std::cerr << ex.what() << std::endl;
        return {Response::Type::GENERIC_SERVER_ERROR, ex.serialize(),
                request.messageNumber};
    }
}

Response Server::handleUserRequest(const std::string &username, const Request &request) {
    //todo do other stuff with open connections only
    try {
        switch (request.type) {
            case Request::Type::GET_ONLINE:
                //todo obtain user list
                break;
            default:
                throw Error("Invalid operation.");
        }
    } catch (Error &ex) {
        std::cerr << ex.what() << std::endl;
        return {Response::Type::GENERIC_SERVER_ERROR, ex.serialize(),
                request.messageNumber};
    }
    return {};
}

uint32_t Server::establishConnection() {
    return 42;
}

void Server::terminateConnection(uint32_t cid) {

}

Response Server::registerUser(const Request &request) {
    RegisterRequest registerRequest =
            RegisterRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, registerRequest.publicKey);
    if (!_database->select(userData).empty()) {
        throw Error("User " + userData.name + " is already registered.");
    }

    Challenge challenge{userData, _random.get(CHALLENGE_SECRET_LENGTH)};
    bool inserted = _registrations.emplace(userData.name, challenge).second;
    if (!inserted) {
        throw Error(
                "User " + userData.name + " is already in the process of verification.");
    }

    return {Response::Type::CHALLENGE_RESPONSE_NEEDED, challenge.secret,
            request.messageNumber};
}

Response Server::completeUserRegistration(const Request &request) {
    CompleteRegistrationRequest curRequest =
            CompleteRegistrationRequest::deserialize(request.payload);

    auto registration = _registrations.find(curRequest.name);
    if (registration == _registrations.end()) {
        throw Error("No pending registration for provided username.");
    }

    if (curRequest.secret != registration->second.secret) {
        throw Error("Cannot verify public key owner.");
    }

    _database->insert(registration->second.userData);

    _connections[curRequest.name].username = registration->second.userData.name;
    _transmission->registerConnection(curRequest.name);
    _registrations.erase(curRequest.name);

    return {Response::Type::OK, {}, request.messageNumber};
}

Response Server::authenticateUser(const Request &request) {
    AuthenticateRequest authenticateRequest =
            AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, {});
    if (_database->select(userData).empty()) {
        throw Error("User with given name is not registered.");
    }

    Challenge challenge{userData, _random.get(CHALLENGE_SECRET_LENGTH)};
    bool inserted = _authentications.emplace(authenticateRequest.name, challenge).second;
    if (!inserted) {
        throw Error(
                "User with given name is already in the process of verification.");
    }
    return {Response::Type::CHALLENGE_RESPONSE_NEEDED, challenge.secret,
            request.messageNumber};
}

Response Server::completeUserAuthentication(const Request &request) {
    CompleteRegistrationRequest curRequest =
            CompleteRegistrationRequest::deserialize(request.payload);

    auto authentication = _authentications.find(curRequest.name);
    if (authentication == _authentications.end()) {
        throw Error("No pending authentication for provided username.");
    }

    if (curRequest.secret != authentication->second.secret) {
        throw Error("Cannot verify public key owner.");
    }

    _connections[curRequest.name].username = authentication->second.userData.name;
    _transmission->registerConnection(curRequest.name);
    _authentications.erase(curRequest.name);

    return {Response::Type::OK, {}, request.messageNumber};
}

Response Server::getOnline(const Request &request) {
    CompleteRegistrationRequest curRequest =
            CompleteRegistrationRequest::deserialize(request.payload);

    auto authentication = _authentications.find(curRequest.name);
    if (authentication == _authentications.end()) {
        throw Error("No pending authentication for provided username.");
    }

    if (curRequest.secret != authentication->second.secret) {
        throw Error("Cannot verify public key owner.");
    }

    _connections[curRequest.name].username = authentication->second.userData.name;
    _transmission->registerConnection(curRequest.name);
    _authentications.erase(curRequest.name);

    return {Response::Type::OK, {}, request.messageNumber};
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
