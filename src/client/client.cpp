#include <ctime>
#include <chrono>
#include "client.h"
#include "../shared/responses.h"
#include "../shared/curve_25519.h"

#include "../shared/X3DH.h"


namespace helloworld {

Client::Client(std::string username, const std::string &serverPubKeyFilename,
               const std::string &clientPrivKeyFilename,
               const std::string &password)
        : _username(std::move(username)),
          _pwd(password),
          _sessionKey(to_hex(Random().get(SYMMETRIC_KEY_SIZE))),
          _transmission(std::make_unique<ClientFiles>(this, _username)),
          _serverPubKey(serverPubKeyFilename),
          _password(password) {
    _rsa.loadPrivateKey(clientPrivKeyFilename, password);
}

void Client::callback(std::stringstream &&data) {
    Response response = _connection->parseIncoming(std::move(data));
    switch (response.header.type) {
        case Response::Type::OK:
            return;
        case Response::Type::USERLIST:
            parseUsers(response);
            return;
        case Response::Type::CHALLENGE_RESPONSE_NEEDED:
            sendRequest(completeAuth(response.payload,
                    (_userId == 0) ? Request::Type::CREATE_COMPLETE : Request::Type::LOGIN_COMPLETE));
            return;
        case Response::Type::USER_REGISTERED:
            _userId = response.header.userId;
            return;
        case Response::Type::BUNDLE_UPDATE_NEEDED:
            _userId = response.header.userId;
            sendKeysBundle();
            return;
        case Response::Type::RECEIVER_BUNDLE:
            //todo attrib only response as the response contains id, for now just to emphasize
            //todo that response has receiver's (to whom we send message) id in header
            sendInitialMessage(response.header.userId, response);
            return;
        default:
            throw Error("Unknown response type.");
    }
}

void Client::login() {
    _connection = std::make_unique<ClientToServerManager>(_sessionKey, _serverPubKey);
    AuthenticateRequest request(_username, {});
    sendRequest({{Request::Type::LOGIN, 1, _userId}, request.serialize()});
}

void Client::logout() {
    GenericRequest request(_userId, _username);
    sendRequest({{Request::Type::LOGOUT, 0, _userId}, request.serialize()});
}

void Client::createAccount(const std::string &pubKeyFilename) {
    _connection = std::make_unique<ClientToServerManager>(_sessionKey, _serverPubKey);
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(_username, key);

    sendRequest({{Request::Type::CREATE, 1, 0}, registerRequest.serialize()});
    _userId = 0;
}

void Client::deleteAccount() {
    GenericRequest request(_userId, _username);
    sendRequest({{Request::Type::REMOVE, 0, _userId}, request.serialize()});
    _userId = 0;
}

void Client::sendFindUsers(const std::string &query) {
    GetUsers request{_userId, _username, query};
    sendRequest({{Request::Type::FIND_USERS, 0, _userId}, request.serialize()});
}

void Client::sendGetOnline() {
    sendGenericRequest(Request::Type::GET_ONLINE);
}

KeyBundle<C25519> Client::updateKeys() {
    const int numberOfOneTimeKeys = 20;

    KeyBundle<C25519> newKeybundle;

    std::ifstream temp("identityKey.pub", std::ios::binary | std::ios::in);

    if (temp.is_open()) {
        if (!temp)  throw Error("cannot access identity key file");
        newKeybundle.identityKey.resize(C25519::KEY_BYTES_LEN);
        read_n(temp, newKeybundle.identityKey.data(), C25519::KEY_BYTES_LEN);
        temp.close();
    } else {
        C25519KeyGen identityKeyGen{};
        identityKeyGen.savePrivateKeyPassword("identityKey.key", _password);
        identityKeyGen.savePublicKey("identityKey.pub");
        newKeybundle.identityKey = identityKeyGen.getPublicKey();
    }

    C25519 identity{};
    identity.loadPrivateKey("identityKey.key", _password);
    identity.loadPublicKey("identityKey.pub");


    temp.open("preKey.pub", std::ios::binary | std::ios::in);

    if (temp.is_open()) {
        if (!temp)  throw Error("cannot access old public pre key file");
        std::ofstream oldpublic("preKey.pub.old", std::ios::binary | std::ios::out);
        oldpublic << temp.rdbuf();

        temp.close();
        temp.open("preKey.key", std::ios::binary | std::ios::in);
        if (!temp)  throw Error("cannot access old public pre key file");
        std::ofstream oldprivate("preKey.pub.old", std::ios::binary | std::ios::out);
        oldprivate << temp.rdbuf();
        temp.close();
    }
    C25519KeyGen preKeyGen{};
    preKeyGen.savePrivateKeyPassword("preKey.key", _password);
    preKeyGen.savePublicKey("preKey.pub");

    newKeybundle.preKey = preKeyGen.getPublicKey();

    newKeybundle.preKeySingiture = identity.sign(newKeybundle.preKey);

    for (int i = 0; i < numberOfOneTimeKeys; ++i) {
        C25519KeyGen oneTimeKeygen{};
        std::vector<unsigned char> onetimeKey = oneTimeKeygen.getPublicKey();
        oneTimeKeygen.savePublicKey("oneTime" + std::to_string(i) + ".pub");
        oneTimeKeygen.savePrivateKeyPassword("oneTime" + std::to_string(i) + ".key", _password);
        newKeybundle.oneTimeKeys.emplace_back(std::move(onetimeKey));
    }

    return std::move(newKeybundle);
}

void Client::sendKeysBundle() {
    KeyBundle<C25519> bundle = updateKeys();
    sendRequest({{Request::Type::KEY_BUNDLE_UPDATE, 0, _userId}, bundle.serialize()});
}

void Client::requestKeyBundle(uint32_t userId) {
    //todo
    sendRequest({});
}

void Client::sendData(uint32_t receiverId, const std::vector<unsigned char> &data) {
    if (_usersSession->running()) {
        //todo double ratchet
    } else {
        std::ifstream in {std::to_string(receiverId) + ".msg", std::ios::binary};
        if (in)
            throw Error("There are messages waiting to be send.");
        in.close();
        std::ofstream out {std::to_string(receiverId) + ".msg", std::ios::binary};
        write_n(out, data);
        requestKeyBundle(receiverId);
    }
}

void Client::sendInitialMessage(uint32_t receiverId, const Response& response) {
    KeyBundle<C25519> bundle = KeyBundle<C25519>::deserialize(response.payload);

    std::ifstream in {std::to_string(receiverId) + ".msg", std::ios::binary};
    if (!in)
        throw Error("There are no messages to be send.");
    size_t size = getSize(in);
    std::vector<unsigned char> data(size);
    read_n(in, data.data(), data.size());

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string time = std::ctime(&now);
    SendData toSend(time, _username, data);

    X3DH protocol;
    X3DHRequest<C25519> request;
    std::string key = protocol.out(_pwd, toSend, bundle, request);

    sendRequest({{Request::Type::SEND, 0, receiverId}, request.serialize()});
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
    GenericRequest request{_userId, _username};
    sendRequest({{type, 0, _userId}, request.serialize()});
}

Request Client::completeAuth(const std::vector<unsigned char> &secret,
                             Request::Type type) {
    CompleteAuthRequest request(_rsa.sign(secret), _username);
    return {{type, 2, _userId}, request.serialize()};
}

}    // namespace helloworld
