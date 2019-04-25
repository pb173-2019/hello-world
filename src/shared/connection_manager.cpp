#include "connection_manager.h"

#include "requests.h"

namespace helloworld {

ClientToServerManager::ClientToServerManager(const std::string& sessionKey,
        const std::string &pubkeyFilename) : BasicConnectionManager(sessionKey) {
    _rsa_out.loadPublicKey(pubkeyFilename);
}

ClientToServerManager::ClientToServerManager(const std::string& sessionKey,
        const std::vector<unsigned char> &publicKeyData)  : BasicConnectionManager(sessionKey) {
    _rsa_out.setPublicKey(publicKeyData);
}

Response ClientToServerManager::parseIncoming(std::stringstream &&data) {

    if (getSize(data) < HEADER_ENCRYPTED_SIZE)
        throw Error("Server returned generic error.");
    std::stringstream headDecrypted = _GCMdecryptHead(data);
    std::stringstream bodyDecrypted = _GCMdecryptBody(data);

    Response response;
    std::vector<unsigned char> head(sizeof(Request::Header));
    read_n(headDecrypted, head.data(), head.size());
    response.header = Response::Header::deserialize(head);
    if (!_testing && !_counter.checkIncomming(response))
        throw Error("Possible replay attack");

    //will pass only encrypted payload if not for server to read
    response.payload.resize(getSize(bodyDecrypted));
    read_n(bodyDecrypted, response.payload.data(), response.payload.size());

    return response;
}

std::stringstream ClientToServerManager::parseOutgoing(Request data) {
    std::stringstream result{};

    // data cannot be const ref - cannot set number
    _counter.setNumber(data);
    if (_established) {
        _GCMencryptHead(result, data);
        _GCMencryptBody(result, data);
    } else {
        //this section sent only once: when registered / authenticated
        write_n(result, _rsa_out.encrypt(from_hex(_sessionKey)));
        write_n(result, _rsa_out.encrypt(data.header.serialize()));
        write_n(result, data.payload);
        //session key sent, switch to secure state
        switchSecureChannel(true);
    }
    result.seekg(0, std::ios::beg);
    return result;
}

GenericServerManager::GenericServerManager(const std::string &privkeyFilename, const std::string &key,
                                           const std::string &iv) : BasicConnectionManager("") {
    _rsa_in.loadPrivateKey(privkeyFilename, key, iv);
}

Request GenericServerManager::parseIncoming(std::stringstream &&data) {
    Request request;
    //encrypted session key
    std::vector<unsigned char> sessionKey = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
    read_n(data, sessionKey.data(), sessionKey.size());
    sessionKey = _rsa_in.decrypt(sessionKey);
    //encrypted head
    std::vector<unsigned char> header = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
    read_n(data, header.data(), header.size());
    header = _rsa_in.decrypt(header);

    request.header = std::move(Request::Header::deserialize(header));

    /* is used for all users, message counting doesnt make sense*/

    size_t length = getSize(data);
    request.payload = std::vector<unsigned char>(length);
    read_n(data, request.payload.data(), length);

    AuthenticateRequest temp = AuthenticateRequest::deserialize(request.payload);
    temp.sessionKey = to_hex(sessionKey);

    request.payload = temp.serialize();
    return request;
}

std::stringstream GenericServerManager::returnErrorGeneric() {
    //empty stream to indicate generic error
    return std::stringstream{};
}

void GenericServerManager::setKey(const std::string &key) {
    _sessionKey = key;
}

std::stringstream GenericServerManager::parseOutgoing(Response data) {
    std::stringstream result{};
    _counter.setNumber(data);
    _GCMencryptHead(result, data);
    _GCMencryptBody(result, data);
    result.seekg(0, std::ios::beg);
    _sessionKey = ""; //reset key to nothing, prevent misuse
    return result;
}

ServerToClientManager::ServerToClientManager(const std::string &sessionKey) : BasicConnectionManager(sessionKey) {
    switchSecureChannel(true);
}

Request ServerToClientManager::parseIncoming(std::stringstream &&data) {
    Request request;

    std::stringstream headDecrypted = _GCMdecryptHead(data);
    std::stringstream bodyDecrypted = _GCMdecryptBody(data);

    std::vector<unsigned char> head(sizeof(Request::Header));
    read_n(headDecrypted, head.data(), head.size());
    request.header = Request::Header::deserialize(head);
    if (!_testing && !_counter.checkIncomming(request))
        throw Error("Possible replay attack");

    //will pass only encrypted payload if not for server to read
    request.payload.resize(getSize(bodyDecrypted));
    read_n(bodyDecrypted, request.payload.data(), request.payload.size());

    return request;
}

std::stringstream ServerToClientManager::parseOutgoing(Response data) {
    std::stringstream result{};
    _counter.setNumber(data);
    _GCMencryptHead(result, data);
    _GCMencryptBody(result, data);
    return result;
}

}
