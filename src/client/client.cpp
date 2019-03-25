#include "client.h"

namespace helloworld {

Client::Client(std::string username, const std::string &serverPubKeyFilename,
               const std::string &clientPrivKeyFilename,
               const std::string &password)
    : _username(std::move(username)),
      _sessionKey(to_hex(Random().get(SYMMETRIC_KEY_SIZE))),
      _transmission(std::make_unique<ClientFiles>(this, _username)),
      _connection(serverPubKeyFilename) {
    _rsa.loadPrivateKey(clientPrivKeyFilename, password);
}

void Client::callback(std::stringstream &&data) {
    Response response = _connection.parseIncoming(std::move(data));
    switch (response.header.type) {
        case Response::Type::OK:
            return;
        case Response::Type::CHALLENGE_RESPONSE_NEEDED:
            _connection.openSecureChannel(_sessionKey);
            sendRequest(completeAuth(response.payload, Request::Type::CREATE_COMPLETE));
            return;
        default:
            throw Error("Unknown response type.");
    }
}

void Client::login() {
    AuthenticateRequest request(_username, _sessionKey);
    sendRequest({{Request::Type::LOGIN, 1, 0}, request.serialize()});
}

void Client::logout() {
    NameIdNeededRequest request(0, _username);
    sendRequest({{Request::Type::LOGOUT, 0, 0}, request.serialize()});
}

void Client::createAccount(const std::string &pubKeyFilename) {
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    RegisterRequest registerRequest(_username, _sessionKey, key);

    sendRequest({{Request::Type::CREATE, 1, 0}, registerRequest.serialize()});
}

void Client::deleteAccount() {
    NameIdNeededRequest request(0, _username);
    sendRequest({{Request::Type::REMOVE, 0, 0}, request.serialize()});
}

std::vector<UserData> Client::getUsers(const std::string &query) { return {}; }

void Client::sendRequest(const Request &request) {
    auto data = _connection.parseOutgoing(request);
    _transmission->send(data);
}

Request Client::completeAuth(const std::vector<unsigned char> &secret,
                             Request::Type type) {
    CompleteAuthRequest request(_rsa.decrypt(secret), _username);
    return {{type, 2, 0}, request.serialize()};
}

}    // namespace helloworld
