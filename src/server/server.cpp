#include <utility>

#include "server.h"
#include "../shared/serializable_error.h"
#include "file_database.h"
#include "requests.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<FileDatabase>("test_db1.db")),
                   _transmission(std::make_unique<FileManager>(this)) {}

void Server::setSessionKey(unsigned long connectionId,
                           std::vector<unsigned char> sessionKey) {
    _connections[connectionId].sessionKey = std::move(sessionKey);
}

Response Server::handleUserRequest(const Request &request) {
    try {
        switch (request.type) {
            case Request::Type::CREATE:
                return registerUser(0, request);
            case Request::Type::CREATE_COMPLETE:
                return completeUserRegistration(0, request);
            case Request::Type::LOGIN:
                return authenticateUser(0, request);
            case Request::Type::LOGIN_COMPLETE:
                return completeUserAuthentication(0, request);
            default:
                throw Error("Invalid operation.");
        }
    } catch (Error &ex) {
        std::cerr << ex.what() << std::endl;
        return {Response::Type::GENERIC_SERVER_ERROR, ex.serialize(),
                request.messageNumber};
    }
}

Response Server::handleUserRequest(unsigned long connectionId, const Request &request) {
    //todo do other stuff with open connections only
    try {
        switch (request.type) {
            case Request::Type::CREATE:
                return registerUser(connectionId, request);
            case Request::Type::CREATE_COMPLETE:
                return completeUserRegistration(connectionId, request);
            case Request::Type::LOGIN:
                return authenticateUser(connectionId, request);
            case Request::Type::LOGIN_COMPLETE:
                return completeUserAuthentication(connectionId, request);
            default:
                throw Error("Unimplemented operation.");
        }
    } catch (Error &ex) {
        std::cerr << ex.what() << std::endl;
        return {Response::Type::GENERIC_SERVER_ERROR, ex.serialize(),
                request.messageNumber};
    }
}

unsigned long Server::establishConnection() {
    return 42;
}

void Server::terminateConnection(unsigned long cid) {

}

Response Server::registerUser(unsigned long connectionId, const Request &request) {
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

Response Server::completeUserRegistration(unsigned long connectionId,
                                          const Request &request) {
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
    _connections[connectionId].username = registration->second.userData.name;
    _registrations.erase(curRequest.name);

    return {Response::Type::OK, {}, request.messageNumber};
}

Response Server::authenticateUser(unsigned long connectionId, const Request &request) {
    AuthenticateRequest authenticateRequest =
        AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, {});
    if (_database->select(userData).empty()) {
        throw Error("User with given name is not registered.");
    }

    Challenge challenge{userData, _random.get(CHALLENGE_SECRET_LENGTH)};
    bool inserted = _authentications.emplace(connectionId, challenge).second;
    if (!inserted) {
        throw Error(
            "User with given name is already in the process of verification.");
    }
    return {Response::Type::CHALLENGE_RESPONSE_NEEDED, challenge.secret,
            request.messageNumber};
}

Response Server::completeUserAuthentication(unsigned long connectionId,
                                            const Request &request) {
    CompleteRegistrationRequest curRequest =
        CompleteRegistrationRequest::deserialize(request.payload);

    auto authentication = _authentications.find(connectionId);
    if (authentication == _authentications.end()) {
        throw Error("No pending authentication for provided username.");
    }

    if (curRequest.secret != authentication->second.secret) {
        throw Error("Cannot verify public key owner.");
    }

    _connections[connectionId].username = authentication->second.userData.name;
    _authentications.erase(connectionId);

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
