#include "server.h"
#include "../shared/server_error.h"
#include "file_database.h"
#include "requests.h"

namespace helloworld {

Server::Server() : _database(std::make_unique<FileDatabase>("test_db1.db")) {}

void Server::setSessionKey(int connectionId,
                           std::vector<unsigned char> sessionKey) {
    _connections[connectionId].sessionKey = sessionKey;
}

Response Server::handleUserRequest(int connectionId, const Request &request) {
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
                throw ServerError("Unimplemented operation.");
        }
    } catch (ServerError &ex) {
        std::cerr << ex.what() << std::endl;
        return {Response::Type::SERVER_ERROR, ex.serialize(),
                request.messageNumber};
    }
}

int Server::establishConnection() { return 42; }

void Server::terminateConnection(int cid) {}

Response Server::registerUser(int connectionId, const Request &request) {
    RegisterRequest registerRequest =
        RegisterRequest::deserialize(request.payload);

    UserData userData(0, registerRequest.name, registerRequest.publicKey);
    if (!_database->select(userData).empty()) {
        throw ServerError("User " + userData.name + " is already registered.");
    }

    Challenge challenge{userData, _random.get(CHALLENGE_SECRET_LENGTH)};
    bool inserted = _registrations.emplace(userData.name, challenge).second;
    if (!inserted) {
        throw ServerError(
            "User " + userData.name + " is already in the process of verification.");
    }

    return {Response::Type::CHALLENGE_RESPONSE_NEEDED, challenge.secret,
            request.messageNumber};
}

Response Server::completeUserRegistration(int connectionId,
                                          const Request &request) {
    CompleteRegistrationRequest curRequest =
        CompleteRegistrationRequest::deserialize(request.payload);

    auto registration = _registrations.find(curRequest.name);
    if (registration == _registrations.end()) {
        throw ServerError("No pending registration for provided username.");
    }

    if (curRequest.secret != registration->second.secret) {
        throw ServerError("Cannot verify public key owner.");
    }

    _database->insert(registration->second.userData);
    _registrations.erase(curRequest.name);
    _connections[connectionId].username = registration->second.userData.name;

    return {Response::Type::OK, {}, request.messageNumber};
}

Response Server::authenticateUser(int connectionId, const Request &request) {
    AuthenticateRequest authenticateRequest =
        AuthenticateRequest::deserialize(request.payload);

    UserData userData(0, authenticateRequest.name, {});
    if (_database->select(userData).empty()) {
        throw ServerError("User with given name is not registered.");
    }

    Challenge challenge{userData, _random.get(CHALLENGE_SECRET_LENGTH)};
    bool inserted = _authentications.emplace(connectionId, challenge).second;
    if (!inserted) {
        throw ServerError(
            "User with given name is already in the process of verification.");
    }
    return {Response::Type::CHALLENGE_RESPONSE_NEEDED, challenge.secret,
            request.messageNumber};
}

Response Server::completeUserAuthentication(int connectionId,
                                            const Request &request) {
    CompleteRegistrationRequest curRequest =
        CompleteRegistrationRequest::deserialize(request.payload);

    auto authentication = _authentications.find(connectionId);
    if (authentication == _authentications.end()) {
        throw ServerError("No pending authentication for provided username.");
    }

    if (curRequest.secret != authentication->second.secret) {
        throw ServerError("Cannot verify public key owner.");
    }

    _authentications.erase(connectionId);
    _connections[connectionId].username = authentication->second.userData.name;

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
