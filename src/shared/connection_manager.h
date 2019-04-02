#include <utility>

/**
 * @file ConnectionManager.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Connection manager takes care of
 *         - parsing the requests and responses
 *         - encryption & decryption using asymmetric cipher if no symmetric keys set (before channel establishment)
 *         - encryption & decryption using symmetric cipher if keys set (when is channel running)
 *         - key derivation, e.g. double ratchet process to derive new keys each message
 * @version 0.1
 * @date 22. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_CONNECTIONMANAGER_H_
#define HELLOWORLD_SHARED_CONNECTIONMANAGER_H_

#include <sstream>
#include <map>
#include <iterator>

#include "request_response.h"
#include "rsa_2048.h"
#include "aes_gcm.h"

namespace helloworld {

/**
 * STRUCTURE:
 * ConnectionManager - helds random, gcm and session key instance,
 * provides basic GCM encryption routines (encrypt head, body)
 *     - BasicConnectionManager - message counting
 *          - ClientToServerManager - first message send is always encrypted with server public key (RSA),
 *          next are encrypted with GCM, use switchSecureChannel(bool) to switch between states
 *
 *          - ServerToClientManager - knows only GCM encryption, handles the session communication
 *
 *     - GenericServerManager - takes care of first requests & error handling
 *     when no connection established available for target user
 */

template<typename incoming, typename outgoing>
class ConnectionManager {
protected:

    AESGCM _gcm{};
    Random _random;

    std::string _sessionKey;
    bool _established = false;

    static constexpr int HEADER_ENCRYPTED_SIZE = 28;
public:
    explicit ConnectionManager(std::string sessionKey) : _sessionKey(std::move(sessionKey)) {};

    virtual ~ConnectionManager() = default;

    /**
     * @brief Initialize security channel once the symmetric key is agreed on
     *
     * @param key symmetric key used by both sides to encrypt the first message
     *        use empty string to close channel
     */
    void switchSecureChannel(bool setEstablished) {
        _established = setEstablished;
    }

    /**
   * @brief Parse bytes into incoming (request/response) type structure,
   *    decrypt and verify integrity
   *
   * @param data
   * @return
   */
    virtual incoming parseIncoming(std::stringstream &&data) = 0;

    /**
     * @brief Parse outgoing (request/response) type structure into byte array,
     *    encrypt and add integrity check
     *
     * @param data
     * @return
     */
    virtual std::stringstream parseOutgoing(const outgoing &data) = 0;

protected:
    //pretty ugly, but C++ does not simply allows to move n bytes
    std::stringstream _nBytesFromStream(std::istream &input, size_t n) {
        std::stringstream result;
        std::vector<unsigned char> buff(n);
        size_t size = read_n(input, buff.data(), buff.size());
        write_n(result, buff.data(), size);
        clear<unsigned char>(buff.data(), buff.size());
        return result;
    }

    void _GCMencryptBody(std::ostream &out, const outgoing &data) {
        std::stringstream body;
        write_n(body, data.payload);
        std::string bodyIv = to_hex(_random.get(AESGCM::iv_size));
        std::istringstream bodyIvStream{bodyIv};
        std::stringstream bodyEncrypted;
        if (!_gcm.setKey(_sessionKey) || !_gcm.setIv(bodyIv)) {
            throw Error("Could not initialize GCM.");
        }
        write_n(out, bodyIv);
        _gcm.encryptWithAd(body, bodyIvStream, out);
    }

    void _GCMencryptHead(std::ostream &out, const outgoing &data) {
        std::vector<unsigned char> head_data = data.header.serialize();
        std::stringstream head;
        write_n(head, head_data);

        //1) encrypt head
        std::string headIv = to_hex(_random.get(AESGCM::iv_size));
        std::istringstream headIvStream{headIv};
        std::stringstream headEncrypted;
        if (!_gcm.setKey(_sessionKey) || !_gcm.setIv(headIv)) {
            throw Error("Could not initialize GCM.");
        }
        write_n(out, headIv);
        _gcm.encryptWithAd(head, headIvStream, out);
    }

    std::stringstream _GCMdecryptHead(std::istream &in) {
        //in hex string - 2x length
        std::stringstream headIvStream = _nBytesFromStream(in, AESGCM::iv_size * 2);
        std::stringstream headStream = _nBytesFromStream(in, HEADER_ENCRYPTED_SIZE);
        std::stringstream headDecrypted;
        if (!_gcm.setKey(_sessionKey) || !_gcm.setIv(headIvStream.str())) {
            throw Error("Could not initialize GCM.");
        }
        headIvStream.seekg(0, std::ios::beg);
        _gcm.decryptWithAd(headStream, headIvStream, headDecrypted);
        return headDecrypted;
    }

    std::stringstream _GCMdecryptBody(std::istream &in) {
        std::stringstream bodyIvStream = _nBytesFromStream(in, AESGCM::iv_size * 2);
        std::stringstream bodyStream = _nBytesFromStream(in, getSize(in));
        std::stringstream bodyDecrypted;
        if (!_gcm.setKey(_sessionKey) || !_gcm.setIv(bodyIvStream.str())) {
            throw Error("Could not initialize GCM.");
        }
        bodyIvStream.seekg(0, std::ios::beg);
        _gcm.decryptWithAd(bodyStream, bodyIvStream, bodyDecrypted);
        return bodyDecrypted;
    }
};


template<typename incoming, typename outgoing>
class BasicConnectionManager : public ConnectionManager<incoming, outgoing> {
protected:

    //todo implement
    MessageNumberGenerator _counter;

public:
    /**
     * Initialize with session key
     *
     * @param sessionKey session key to use
     */
    explicit BasicConnectionManager(const std::string &sessionKey)
            : ConnectionManager<incoming, outgoing>(sessionKey) {};

};

/**
 * Client side implementation with connections to other clients as well
 */
class ClientToServerManager : public ConnectionManager<Response, Request> {

    //outgoing RSA initialized with server public key
    RSA2048 _rsa_out{};

    //will perform double ratchet
//    ClientToClientManager manager;

public:
    /**
     * @brief Initialize with keys from files
     *
     * @param pubkeyFilename rsa public key of the receiver filename path
     * @param privkeyFilename rsa private key of the owner filename path
     * @param pwd password to decrypt private key
     */
    explicit ClientToServerManager(const std::string &sessionKey, const std::string &pubkeyFilename);

    /**
     * @brief Initialize with public key from buffer
     *
     * @param publicKeyData buffer with public key in pem format (e.g. pem file loaded into buffer)
     * @param privkeyFilename rsa private key of the owner filename path
     * @param pwd password to decrypt private key
     */
    explicit ClientToServerManager(const std::string &sessionKey, const std::vector<unsigned char> &publicKeyData);

    Response parseIncoming(std::stringstream &&data) override;

    std::stringstream parseOutgoing(const Request &data) override;

private:

};

/**
 * Server side implementation with connection to one client at time
 * server always knows the session key as it is forwarded in auth / registration
 */
class ServerToClientManager : public ConnectionManager<Request, Response> {
public:
    explicit ServerToClientManager(const std::string &sessionKey);

    Request parseIncoming(std::stringstream &&data) override;

    std::stringstream parseOutgoing(const Response &data) override;
};

/**
 * Class that is meant to parse only with server private key - incoming registration & request
 */
class GenericServerManager : ConnectionManager<Request, Response> {

    RSA2048 _rsa_in{};

public:
    /**
     * Server manager that takes care of generic events, such as when the session
     * is not established
     *
     * @param privkeyFilename server private key file name
     * @param key aes key to read private key
     * @param iv aes iv to read private key
     */
    GenericServerManager(const std::string &privkeyFilename, const std::string &key, const std::string &iv);

    /**
     * Parse incomming request with server private key
     * @param data data to parse
     * @return Request from new user
     */
    Request parseIncoming(std::stringstream &&data) override;

    /**
     * Return reponse bytes of 0s that satisfies the parsed reponse length
     * @return stream of 0s
     */
    std::stringstream returnErrorGeneric();

    /**
     * Serves as generic parser when key known, but
     * connection manager is not present, uses key given
     * in setKey method, which must be called before this
     * one is used, the session key is deleted when data sent
     *
     * @param data data to parse & encrypt
     * @param key GCM key to encrypt
     * @return stream
     */
    std::stringstream parseOutgoing(const Response &data) override;

    /**
     * Set gcm key for parseOutgoing(const Response &data) method
     * @param key
     */
    void setKey(const std::string& key);
};

}

#endif //HELLOWORLD_SHARED_CONNECTIONMANAGER_H_
