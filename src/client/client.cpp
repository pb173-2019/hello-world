#include "client.h"
#include <chrono>
#include <ctime>
#include <tuple>
#include <QMetaMethod>

#include "config.h"

#include "../shared/curve_25519.h"
#include "../shared/responses.h"

namespace helloworld {

Client::Client(std::string username,
            const std::string &clientPrivKeyFilename,
            const std::string &password,
            QObject *parent)
    : QObject(parent),
      _username(std::move(username)),
      _password(password),
      _x3dh(std::make_unique<X3DH>(_username, _password)) {

    _rsa.loadPrivateKey(clientPrivKeyFilename, password);
}

void Client::callback(std::stringstream &&data) {
    Response response;
    try {
        response = _connection->parseIncoming(std::move(data));
    } catch (Error& ex) {
        static const QMetaMethod valueChangedSignal = QMetaMethod::fromSignal(&Client::error);
        if (QObject::isSignalConnected(valueChangedSignal)) {
            emit error(ex.what());
            return;
        }
        throw ex;
    }
    if (_userId == 0)
        _userId = response.header.userId;
    switch (response.header.type) {
        case Response::Type::OK:
            return;
        case Response::Type::USERLIST:
            parseUsers(response);
            return;
        case Response::Type::CHALLENGE_RESPONSE_NEEDED:
            sendRequest(completeAuth(response.payload,
                                      Request::Type::CREATE_COMPLETE)); // change create complete to auth complete
            return;
        case Response::Type::USER_REGISTERED:
            _userId = response.header.userId;
            sendKeysBundle();
            return;
        case Response::Type::BUNDLE_UPDATE_NEEDED:
            sendKeysBundle();
            return;
        case Response::Type::RECEIVER_BUNDLE_SENT:
            sendInitialMessage(response);
            return;
        case Response::Type::RECEIVE:
        case Response::Type::RECEIVE_OLD:
            receiveData(response);
            return;
        default:
            throw Error("Unknown response type.");
    }
}

void Client::login() {
    _connection = std::make_unique<ClientToServerManager>(to_hex(Random().get(SYMMETRIC_KEY_SIZE)), serverPub);
    AuthenticateRequest request(_username, {});
    sendRequest({{Request::Type::LOGIN, _userId}, request.serialize()});
}

void Client::logout() {
    GenericRequest request(_userId, _username);
    sendRequest({{Request::Type::LOGOUT, _userId}, request.serialize()});
}

void Client::createAccount(const std::string &pubKeyFilename) {
    _userId = 0;
    _connection = std::make_unique<ClientToServerManager>(to_hex(Random().get(SYMMETRIC_KEY_SIZE)), serverPub);
    std::ifstream input(pubKeyFilename);
    std::string publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    std::vector<unsigned char> key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(_username, key);

    sendRequest({{Request::Type::CREATE, 0}, registerRequest.serialize()});
}

void Client::deleteAccount() {
    GenericRequest request(_userId, _username);
    sendRequest({{Request::Type::REMOVE, _userId}, request.serialize()});
}

void Client::sendFindUsers(const std::string &query) {
    GetUsers request{_userId, _username, query};
    sendRequest({{Request::Type::FIND_USERS, _userId}, request.serialize()});
}

void Client::sendGetOnline() { sendGenericRequest(Request::Type::GET_ONLINE); }

KeyBundle<C25519> Client::updateKeys() {
    const int numberOfOneTimeKeys = 20;
    KeyBundle<C25519> newKeybundle;

    std::ifstream temp(_username + idC25519pub,
                       std::ios::binary | std::ios::in);
    if (temp.is_open()) {
        if (!temp) throw Error("cannot access identity key file");
        newKeybundle.identityKey.resize(C25519::KEY_BYTES_LEN);
        read_n(temp, newKeybundle.identityKey.data(), C25519::KEY_BYTES_LEN);
        temp.close();
    } else {
        C25519KeyGen identityKeyGen{};
        identityKeyGen.savePrivateKeyPassword(_username + idC25519priv,
                                              _password);
        identityKeyGen.savePublicKey(_username + idC25519pub);
        newKeybundle.identityKey = identityKeyGen.getPublicKey();
    }

    archiveKey(_username + preC25519pub);
    archiveKey(_username + preC25519priv);
    C25519KeyGen preKeyGen{};
    preKeyGen.savePrivateKeyPassword(_username + preC25519priv, _password);
    preKeyGen.savePublicKey(_username + preC25519pub);

    newKeybundle.preKey = preKeyGen.getPublicKey();

    C25519 identity{};
    identity.loadPrivateKey(_username + idC25519priv, _password);
    newKeybundle.preKeySingiture = identity.sign(newKeybundle.preKey);

    for (int i = 0; i < numberOfOneTimeKeys; ++i) {
        archiveKey(_username + std::to_string(i) + oneTimeC25519pub);
        archiveKey(_username + std::to_string(i) + oneTimeC25519priv);
        C25519KeyGen oneTimeKeygen{};
        oneTimeKeygen.savePublicKey(_username + std::to_string(i) +
                                    oneTimeC25519pub);
        oneTimeKeygen.savePrivateKeyPassword(
            _username + std::to_string(i) + oneTimeC25519priv, _password);
        newKeybundle.oneTimeKeys.emplace_back(
            std::move(oneTimeKeygen.getPublicKey()));
    }

    newKeybundle.generateTimeStamp();
    _x3dh->setTimestamp(newKeybundle.timestamp);
    return std::move(newKeybundle);
}

void Client::sendKeysBundle() {
    KeyBundle<C25519> bundle = updateKeys();
    sendRequest(
        {{Request::Type::KEY_BUNDLE_UPDATE, _userId}, bundle.serialize()});
}

void Client::requestKeyBundle(uint32_t receiverId) {
    sendRequest({{Request::Type::GET_RECEIVERS_BUNDLE, receiverId},
                 GenericRequest{_userId, _username}.serialize()});
}

void Client::checkForMessages() {
    sendGenericRequest(Request::Type::CHECK_INCOMING);
}

void Client::archiveKey(const std::string &keyFileName) {
    std::ifstream temp(keyFileName, std::ios::binary | std::ios::in);
    if (temp.is_open()) {
        if (!temp) throw Error("cannot access key file: " + keyFileName);
        std::ofstream old(keyFileName + ".old",
                          std::ios::binary | std::ios::out);
        old << temp.rdbuf();
    }
}

void Client::sendData(uint32_t receiverId, const std::vector<unsigned char> &data) {
    if (_doubleRatchetConnection) {
        auto message = _doubleRatchetConnection->RatchetEncrypt(data);
        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::string time = std::ctime(&now);
        SendData toSend(time, _username, message.serialize());
        sendRequest({{Request::Type::SEND, receiverId}, toSend.serialize()});
    } else {
        bool first = true;
        std::ifstream in{std::to_string(receiverId) + ".msg"};
        if (in) first = false;
        in.close();

        //simple message stacking into one file, in future maybe add some separator policy (now using ---)
        std::ofstream out{std::to_string(receiverId) + ".msg", std::ios::binary | std::ios_base::app};
        if (! first)
            out << "---\n";

        write_n(out, data);
        out.close();
        //request only if not requested before (e.g. multiple 1st messages)
        if (first) requestKeyBundle(receiverId);
    }
}

void Client::sendInitialMessage(const Response &response) {
    KeyBundle<C25519> bundle = KeyBundle<C25519>::deserialize(response.payload);

    std::string file = std::to_string(response.header.userId) + ".msg";
    std::ifstream in{file, std::ios::binary};
    if (!in) throw Error("There are no messages to be send.");
    size_t size = getSize(in);
    std::vector<unsigned char> data(size);
    read_n(in, data.data(), data.size());
    in.close();
    remove(file.c_str());

    auto now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string time = std::ctime(&now);
    SendData toSend(time, _username, data);

    X3DHRequest<C25519> request;
    X3DH::X3DHSecretPubKey secret;
    std::tie(request, secret) = _x3dh->setSecret(bundle);
    _doubleRatchetConnection =
        std::make_unique<DoubleRatchet>(secret.sk, secret.ad, secret.pubKey);
    Message message = _doubleRatchetConnection->RatchetEncrypt(toSend.serialize());
    request.AEADenrypted = message.serialize();

    sendRequest({{Request::Type::SEND, response.header.userId}, request.serialize()});
}

void Client::receiveData(const Response &response) {
    if (_doubleRatchetConnection) {
        auto sendData = SendData::deserialize(response.payload);
        auto receivedData = _doubleRatchetConnection->RatchetDecrypt(
            Message::deserialize(sendData.data));
        sendData.data = receivedData;
        _incomming = sendData;
    } else {
        std::vector<unsigned char> messageEncrypted;
        X3DH::X3DHSecretKeyPair secret;
        std::tie(messageEncrypted, secret) = _x3dh->getSecret(response);

        _doubleRatchetConnection = std::make_unique<DoubleRatchet>(
                secret.sk, secret.ad, secret.pubKey, secret.privKey);

        Message message = Message::deserialize(messageEncrypted);
        _incomming = SendData::deserialize(_doubleRatchetConnection->RatchetDecrypt(message));
    }
}


void Client::parseUsers(const helloworld::Response &response) {
    _userList.clear();
    UserListReponse online = UserListReponse::deserialize(response.payload);
    for (size_t i = 0; i < online.ids.size(); i++) {
        _userList[online.ids[i]] = online.online[i];
    }
}

void Client::sendRequest(const Request &request) {
    auto data = _connection->parseOutgoing(request);
    _transmission->send(data);
}

void Client::sendGenericRequest(Request::Type type) {
    GenericRequest request{_userId, _username};
    sendRequest({{type, _userId}, request.serialize()});
}

Request Client::completeAuth(const std::vector<unsigned char> &secret,
                             Request::Type type) {
    CompleteAuthRequest request(_rsa.sign(secret), _username);
    return {{type, _userId}, request.serialize()};
}


void ClientCleaner_Run() {
    std::string leftovers = getFile(".key");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());
        leftovers = getFile(".key");
    }
    leftovers = getFile(".pub");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());leftovers = getFile(".pub");
        leftovers = getFile(".pub");
    }
    leftovers = getFile(".old");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());
        leftovers = getFile(".old");
    }
    leftovers = getFile(".msg");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());
        leftovers = getFile(".msg");
    }
}

}    // namespace helloworld
