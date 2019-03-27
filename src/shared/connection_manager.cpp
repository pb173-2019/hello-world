#include "connection_manager.h"

namespace helloworld {

ClientToServerManager::ClientToServerManager(const std::string &pubkeyFilename) {
    _rsa_out.loadPublicKey(pubkeyFilename);
}

ClientToServerManager::ClientToServerManager(const std::vector<unsigned char> &publicKeyData) {
    _rsa_out.setPublicKey(publicKeyData);
}

Response ClientToServerManager::parseIncoming(std::stringstream &&data) {
    std::stringstream headDecrypted = _GCMdecryptHead(data);
    std::stringstream bodyDecrypted = _GCMdecryptBody(data);

    Response response;
    std::vector<unsigned char> head(sizeof(Request::Header));
    read_n(headDecrypted, head.data(), head.size());
    response.header = Response::Header::deserialize(head);
    //will pass only encrypted payload if not for server to read
    response.payload.resize(getSize(bodyDecrypted));
    read_n(bodyDecrypted, response.payload.data(), response.payload.size());

    return response;
}

std::stringstream ClientToServerManager::parseOutgoing(const Request &data) {
    std::stringstream result{};
    //data.header.messageNumber = _counter.
    if (_sessionKey.length() == AESGCM::key_size * 2) {
        _GCMencryptHead(result, data);
        _GCMencryptBody(result, data);
    } else {
        //when connection starts (registration / login)
        //does not ensure integrity, results in connection failure as we're sending session key
        write_n(result, _rsa_out.encrypt(data.header.serialize()));
        int limit = 126;
        int processed = 0;
        while (processed < data.payload.size()) {
            size_t length = data.payload.size() - processed;
            if (length > limit) length = static_cast<size_t>(limit);
            std::vector<unsigned char> toEncrypt(data.payload.data() + processed,
                                                 data.payload.data() + processed + length);
            write_n(result, _rsa_out.encrypt(toEncrypt));
            processed += limit;
        }
    }
    result.seekg(0, std::ios::beg);
    return result;
}


GenericServerManager::GenericServerManager(const std::string &privkeyFilename, const std::string &key,
                                           const std::string &iv) {
    _rsa_in.loadPrivateKey(privkeyFilename, key, iv);
}

Request GenericServerManager::parseIncoming(std::stringstream &&data) {
    Request request;
    std::vector<unsigned char> header = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
    read_n(data, header.data(), header.size());

    header = _rsa_in.decrypt(header);

    std::vector<unsigned char> body = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
    std::vector<unsigned char> result;
    while (true) {
        size_t read = read_n(data, body.data(), body.size());
        if (read <= 0)
            break;
        std::vector<unsigned char> decrypted = _rsa_in.decrypt(body);
        result.insert(result.end(), decrypted.begin(), decrypted.end());
    }
    request.header = std::move(Request::Header::deserialize(header));
    request.payload = std::move(result);

    return request;
}

std::stringstream GenericServerManager::returnErrorGeneric() {
    std::stringstream result;
    std::fill_n(std::ostream_iterator<char>(result),
                AESGCM::iv_size * 4 + HEADER_ENCRYPTED_SIZE, 'a');
    return result;
}

std::stringstream GenericServerManager::parseErrorGCM(const Response &data, const std::string &key) {
    Random random{};
    AESGCM gcm;

    std::stringstream result{};
    //data.header.messageNumber = _counter.

    std::stringstream body;
    write_n(body, data.payload);

    std::vector<unsigned char> head_data = data.header.serialize();
    std::stringstream head;
    write_n(head, head_data);

    //1) encrypt head
    std::string headIv = to_hex(random.get(AESGCM::iv_size));
    std::istringstream headIvStream{headIv};
    std::stringstream headEncrypted;
    if (!gcm.setKey(key) || !gcm.setIv(headIv)) {
        throw Error("Could not initialize GCM.");
    }
    write_n(result, headIv);
    gcm.encryptWithAd(head, headIvStream, result);

    //2) encrypt body
    std::string bodyIv = to_hex(random.get(AESGCM::iv_size));
    std::istringstream bodyIvStream{bodyIv};
    std::stringstream bodyEncrypted;
    if (!gcm.setKey(key) || !gcm.setIv(bodyIv)) {
        throw Error("Could not initialize GCM.");
    }
    write_n(result, bodyIv);
    gcm.encryptWithAd(body, bodyIvStream, result);
    bodyEncrypted.seekg(0, std::ios::beg);
    bodyIvStream.seekg(0, std::ios::beg);

    result.seekg(0, std::ios::beg);
    return result;
}


ServerToClientManager::ServerToClientManager(const std::string &sessionKey) {
    openSecureChannel(sessionKey);
}

Request ServerToClientManager::parseIncoming(std::stringstream &&data) {
    Request request;
    //data.header.messageNumber = _counter.
    std::stringstream headDecrypted = _GCMdecryptHead(data);
    std::stringstream bodyDecrypted = _GCMdecryptBody(data);

    std::vector<unsigned char> head(sizeof(Request::Header));
    read_n(headDecrypted, head.data(), head.size());
    request.header = Request::Header::deserialize(head);
    //will pass only encrypted payload if not for server to read
    request.payload.resize(getSize(bodyDecrypted));
    read_n(bodyDecrypted, request.payload.data(), request.payload.size());

    return request;
}

std::stringstream ServerToClientManager::parseOutgoing(const Response &data) {
    std::stringstream result{};
    //data.header.messageNumber = _counter.

    _GCMencryptHead(result, data);
    _GCMencryptBody(result, data);
    return result;
}

}
