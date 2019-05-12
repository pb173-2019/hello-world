#include "client.h"
#include <QMetaMethod>
#include <chrono>
#include <ctime>
#include <tuple>

#include "config.h"

#include "../shared/curve_25519.h"
#include "../shared/responses.h"
#include "client_utils.h"

namespace helloworld {
bool Client::_test = false;

Client::Client(std::string username, const std::string &clientPrivKeyFilename,
               const std::string &clientPubKeyFilename,
               const zero::str_t &password, QObject *parent)
    : QObject(parent),
      _timeout(new QTimer(this)),
      _username(std::move(username)),
      _password(password),
      _x3dh(std::make_unique<X3DH>(_username, _password)) {
    _rsa.loadPrivateKey(clientPrivKeyFilename, password);
    _rsa_pub.loadPublicKey(clientPubKeyFilename);
    loadRatchetStates();
    if (!_test) {
        _timeout->setInterval(
            RESET_SESSION_AFTER_MS);    // resets session key every 5 minutes
        connect(_timeout, &QTimer::timeout, [&]() { reauthenticate(); });
    }
}

void Client::reauthenticate() {
    resetSession();
    login();
}

void Client::callback(std::stringstream &&data) {
    Response response;
    try {
        response = _connection->parseIncoming(std::move(data));
    } catch (Error &ex) {
        static const QMetaMethod valueChangedSignal =
            QMetaMethod::fromSignal(&Client::error);
        if (QObject::isSignalConnected(valueChangedSignal)) {
            emit error(ex.what());
            return;
        }
        throw ex;
    }
    if (_userId == 0 && (_userId = response.header.userId) != 0) {
        if (!_test) _timeout->start();
    }
    switch (response.header.type) {
        case Response::Type::OK:
            return;
        case Response::Type::USERLIST:
            parseUsers(response);
            return;
        case Response::Type::CHALLENGE_RESPONSE_NEEDED:
            sendRequest(completeAuth(response.payload));
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
        case Response::Type::GENERIC_SERVER_ERROR:
            throw Error("Server returned error.");
        default:
            throw Error("Unknown response type.");
    }
}

void Client::login() {
    _connection = std::make_unique<ClientToServerManager>(
        to_hex(Random().getKey(SYMMETRIC_KEY_SIZE)), serverPub);
    _connection->_testing = _test;
    AuthenticateRequest request(_username, {});
    sendRequest({{Request::Type::LOGIN, _userId}, request.serialize()});
}

void Client::logout() {
    if (!_test) _timeout->stop();
    sendRequest({{Request::Type::LOGOUT, _userId}, {}});
    _userId = 0;
    _connection.reset(nullptr);
}

void Client::resetSession() {
    if (!_test) _timeout->stop();
    sendRequest({{Request::Type::REESTABLISH_SESSION, _userId}, {}});
    _userId = 0;
    std::move(_connection);
}

void Client::createAccount(const std::string &pubKeyFilename) {
    _userId = 0;
    _connection = std::make_unique<ClientToServerManager>(
        to_hex(Random().getKey(SYMMETRIC_KEY_SIZE)), serverPub);
    if (_test) _connection->_testing = _test;
    std::ifstream input(pubKeyFilename);
    zero::str_t publicKey((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    zero::bytes_t key(publicKey.begin(), publicKey.end());
    AuthenticateRequest registerRequest(_username, key);

    sendRequest({{Request::Type::CREATE, 0}, registerRequest.serialize()});
}

void Client::deleteAccount() {
    GenericRequest request(_userId);
    sendRequest({{Request::Type::REMOVE, _userId}, request.serialize()});
}

void Client::sendFindUsers(const std::string &query) {
    GetUsers request{query};
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
        newKeybundle.oneTimeKeys.emplace_back(oneTimeKeygen.getPublicKey());
    }

    newKeybundle.generateTimeStamp();
    _x3dh->setTimestamp(newKeybundle.timestamp);
    return newKeybundle;
}

void Client::sendKeysBundle() {
    KeyBundle<C25519> bundle = updateKeys();
    sendRequest(
        {{Request::Type::KEY_BUNDLE_UPDATE, _userId}, bundle.serialize()});
}

void Client::requestKeyBundle(uint32_t receiverId) {
    sendRequest({{Request::Type::GET_RECEIVERS_BUNDLE, receiverId}, {}});
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

void Client::saveRatchetStates() {
    zero::bytes_t result;
    ClientState clientState;

    std::transform(_ratchets.begin(), _ratchets.end(),
                   std::back_inserter(clientState.states),
                   [](std::pair<const uint32_t, DoubleRatchet> &p) {
                       return DRStatePair(p.first, p.second.getState());
                   });
    std::transform(_initialMessages.begin(), _initialMessages.end(),
                   std::back_inserter(clientState.messages),
                   [](std::pair<const uint32_t, X3DHRequest<C25519>> &p) {
                       return X3DHInitialMessage(p.first, p.second);
                   });
    std::ofstream state(_username + ".state",
                        std::ios::binary | std::ios::out | std::ios::trunc);

    AESGCM aes;
    zero::bytes_t key = Random().getKey(AESGCM::key_size);
    aes.setIv(to_hex(std::vector<unsigned char>(AESGCM::iv_size, 0)));
    aes.setKey(to_hex(key));
    std::vector<unsigned char> encrypted;
    aes.encryptWithAd(clientState.serialize(), {}, encrypted);

    write_n(state, encrypted);

    std::vector<unsigned char> encryptedKey =
        _rsa_pub.encrypt({key.begin(), key.end()});
    std::ofstream stateKey(_username + ".state.key",
                           std::ios::binary | std::ios::out | std::ios::trunc);
    write_n(stateKey, encryptedKey);
}

void Client::loadRatchetStates() {
    std::ifstream stateKey(_username + ".state.key",
                           std::ios::binary | std::ios::in);
    std::ifstream state(_username + ".state", std::ios::binary | std::ios::in);

    if (!state || !stateKey) {
        return;
    }

    std::vector<unsigned char> keyEncrypted;
    keyEncrypted.resize(getSize(stateKey));
    read_n(stateKey, keyEncrypted.data(), keyEncrypted.size());
    auto decrypted = _rsa.decrypt(keyEncrypted);
    zero::bytes_t key = zero::bytes_t(decrypted.begin(), decrypted.end());

    std::vector<unsigned char> encrypted;
    encrypted.resize(getSize(state));

    AESGCM aes;
    aes.setIv(to_hex(std::vector<unsigned char>(AESGCM::iv_size, 0)));
    aes.setKey(to_hex(key));
    read_n(state, encrypted.data(), encrypted.size());
    std::vector<unsigned char> bytes;
    aes.decryptWithAd(encrypted, {}, bytes);

    uint64_t from = 0;
    auto clientState = ClientState::deserialize(bytes, from);

    std::for_each(clientState.states.begin(), clientState.states.end(),
                  [this](DRStatePair &p) {
                      _ratchets.emplace(p.id, DoubleRatchet(p.state));
                  });
    std::for_each(clientState.messages.begin(), clientState.messages.end(),
                  [this](X3DHInitialMessage &p) {
                      _initialMessages.emplace(p.id, p.message);
                  });
}

void Client::sendData(uint32_t receiverId,
                      const std::vector<unsigned char> &data) {
    if (hasRatchet(receiverId)) {
        DoubleRatchet &ratchet = _ratchets.at(receiverId);
        auto message = _ratchets.at(receiverId).RatchetEncrypt(data);
        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        std::string time = std::ctime(&now);

        if (ratchet.hasReceivedMessage()) {
            _initialMessages.erase(receiverId);
            SendData toSend(time, _username, _userId, false,
                            message.serialize());
            sendRequest({{Request::Type::SEND, receiverId, _userId},
                         toSend.serialize()});
        } else {
            sendX3DHMessage(receiverId, time, message);
        }
    } else {
        bool first = true;
        std::ifstream in{std::to_string(receiverId) + ".msg"};
        if (in) first = false;
        in.close();

        // simple message stacking into one file, in future maybe add some
        // separator policy (now using ---)
        std::ofstream out{std::to_string(receiverId) + ".msg",
                          std::ios::binary | std::ios_base::app};
        if (!first) out << "---\n";

        write_n(out, data);
        out.close();
        // request only if not requested before (e.g. multiple 1st messages)
        if (first) {
            requestKeyBundle(receiverId);
        }
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

    X3DHRequest<C25519> request;
    X3DH::X3DHSecretPubKey secret;
    std::tie(request, secret) = _x3dh->setSecret(bundle);

    _initialMessages[response.header.userId] = request;

    _ratchets.emplace(response.header.userId,
                      DoubleRatchet(secret.sk, secret.ad, secret.pubKey));
    Message message = _ratchets.at(response.header.userId).RatchetEncrypt(data);

    sendX3DHMessage(response.header.userId, time, message);
}

void Client::sendX3DHMessage(uint32_t receiverId, const std::string &time,
                             const Message &message) {
    auto request = _initialMessages.at(receiverId);
    request.AEADenrypted = message.serialize();

    SendData toSend(time, _username, _userId, true, request.serialize());
    sendRequest(
        {{Request::Type::SEND, receiverId, _userId}, toSend.serialize()});
}

void Client::decryptInitialMessage(SendData &sendData, Response::Type type) {
    std::vector<unsigned char> messageEncrypted;
    X3DH::X3DHSecretKeyPair secret;
    std::tie(messageEncrypted, secret) = _x3dh->getSecret(sendData.data);

    if (type == Response::Type::RECEIVE_OLD) {
        DoubleRatchet temp{secret.sk, secret.ad, secret.pubKey, secret.privKey};
        Message message = Message::deserialize(messageEncrypted);
        auto decrypted = temp.RatchetDecrypt(message);
        if (!decrypted.empty()) {
            sendData.data = decrypted;
            _incomming = sendData;
        } else {
            _incomming = {};
        }
    } else {
        _ratchets.emplace(
            sendData.fromId,
            DoubleRatchet(secret.sk, secret.ad, secret.pubKey, secret.privKey));
        Message message = Message::deserialize(messageEncrypted);
        auto decrypted = _ratchets.at(sendData.fromId).RatchetDecrypt(message);
        if (!decrypted.empty()) {
            sendData.data = decrypted;
            _incomming = sendData;
        } else {
            _incomming = {};
        }
    }
}

void Client::receiveData(const Response &response) {
    auto sendData = SendData::deserialize(response.payload);

    if (sendData.x3dh) {
        decryptInitialMessage(sendData, response.header.type);
    } else {
        auto receivedData =
            _ratchets.at(sendData.fromId)
                .RatchetDecrypt(Message::deserialize(sendData.data));
        sendData.data = receivedData;
        _incomming = sendData;
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
    GenericRequest request{_userId};
    sendRequest({{type, _userId}, request.serialize()});
}

Request Client::completeAuth(const std::vector<unsigned char> &secret) {
    CompleteAuthRequest request(_rsa.sign(secret), _username);
    return {{Request::Type::CHALLENGE, _userId}, request.serialize()};
}

bool Client::hasRatchet(uint32_t id) const {
    return _ratchets.find(id) != _ratchets.end();
}

Client::~Client() { saveRatchetStates(); }

void ClientCleaner_Run() {
    std::string leftovers = getFile(".key");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());
        leftovers = getFile(".key");
    }
    leftovers = getFile(".pub");
    while (!leftovers.empty()) {
        remove(leftovers.c_str());
        leftovers = getFile(".pub");
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
