#include "client.h"
#include "../shared/responses.h"

namespace helloworld {

Client::Client(std::string username, const std::string &serverPubKeyFilename,
               const std::string &clientPrivKeyFilename,
               const std::string &password)
        : _username(std::move(username)),
          _sessionKey(to_hex(Random().get(SYMMETRIC_KEY_SIZE))),
          _transmission(std::make_unique<ClientFiles>(this, _username)),
          _serverPubKey(serverPubKeyFilename) {
    _rsa.loadPrivateKey(clientPrivKeyFilename, password);
}

void Client::callback(std::stringstream &&data) {
    Response response = _connection->parseIncoming(std::move(data));
    switch (response.header.type) {
        case Response::Type::OK:
            //todo maybe create response with REGISTRATION_SUCCESFULL to set registration to true
            _isRegistered = true;
            return;
        case Response::Type::DATABASE_USERLIST:
            parseUsers(response);
            return;
        case Response::Type::CHALLENGE_RESPONSE_NEEDED:
            sendRequest(completeAuth(response.payload,
                    (_isRegistered) ? Request::Type::LOGIN_COMPLETE : Request::Type::CREATE_COMPLETE));
            return;
        default:
            throw Error("Unknown response type.");
    }
}

void Client::login() {
    _connection = std::make_unique<ClientToServerManager>(_sessionKey, _serverPubKey);
    AuthenticateRequest request(_username, {});
    sendRequest({{Request::Type::LOGIN, 1, 0}, request.serialize()});
}

void Client::logout() {
    GenericRequest request(0, _username);
    sendRequest({{Request::Type::LOGOUT, 0, 0}, request.serialize()});
}

void Client::createAccount(const std::string &pubKeyFilename) {
    _connection = std::make_unique<ClientToServerManager>(_sessionKey, _serverPubKey);
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(_username, key);

    sendRequest({{Request::Type::CREATE, 1, 0}, registerRequest.serialize()});
    _isRegistered = false;
}

void Client::deleteAccount() {
    GenericRequest request(0, _username);
    sendRequest({{Request::Type::REMOVE, 0, 0}, request.serialize()});
    _isRegistered = false;
}

void Client::sendFindUsers(const std::string &query) {
    GetUsers request{0, _username, query};
    sendRequest({{Request::Type::FIND_USERS, 0, 0}, request.serialize()});
}

void Client::sendGetOnline() {
    sendGenericRequest(Request::Type::GET_ONLINE);
}


void Client::sendKeysBundle() {
    //todo
    sendRequest({});
}

void Client::requestKeyBundle(uint32_t userId) {
    //todo
    sendRequest({});
}

void Client::sendData(uint32_t userId, const std::vector<unsigned char> &data) {
    sendRequest({{Request::Type::SEND, 0, userId}, SendData(_username, data).serialize()});
}

void Client::parseUsers(const helloworld::Response &response) {
    UserListReponse online = UserListReponse::deserialize(response.payload);
    _userList = online.online;
}

void Client::sendRequest(const Request &request) {
    auto data = _connection->parseOutgoing(request);
    _transmission->send(data);
}

void Client::sendGenericRequest(Request::Type type) {
    GenericRequest request{0, _username};
    sendRequest({{type, 0, 0}, request.serialize()});
}

Request Client::completeAuth(const std::vector<unsigned char> &secret,
                             Request::Type type) {
    CompleteAuthRequest request(_rsa.sign(secret), _username);
    return {{type, 2, 0}, request.serialize()};
}

}    // namespace helloworld
