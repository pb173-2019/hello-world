/**
 * @file ConnectionManager.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Connection manager takes care of
 *         - parsing the requests and responses using rrmanip.h
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

#include "request.h"
#include "sha_512.h"
#include "rsa_2048.h"
#include "aes_gcm.h"
#include "hmac.h"

namespace helloworld {
/**
 * body structure parsing in client-client communication
 * will use other keys for encryption than server
 */
    class ClientToClientManager {

    };

/**
 * Request / reponse header parsing & body structure parsing in client-server communication
 */
    template<typename incoming, typename outgoing>
    class ConnectionManager {
    protected:

        std::string _sessionKey;

        bool _established = false;

        AESGCM _gcm{};
        Random _random;

        //counter with random beginning, to accept only newer data
        MessageNumberGenerator _counter;

        static constexpr int HEADER_ENCRYPTED_SIZE = 28;
    public:
        virtual ~ConnectionManager() = default;

        /**
         * @brief Initialize security channel once the symmetric key is agreed on
         *
         * @param key symmetric key used by both sides to encrypt the first message
         */
        void openSecureChannel(std::string key) {
            _gcm.setKey(key);
            _sessionKey = std::move(key);
            _established = true;
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
        std::stringstream nBytesFromStream(std::istream &input, size_t n) {
            std::stringstream result;
            std::vector<unsigned char> buff(n);
            size_t size = read_n(input, buff.data(), buff.size());
            write_n(result, buff.data(), size);
            clear<unsigned char>(buff.data(), buff.size());
            return result;
        }
    };

/**
 * Client side implementation with connections to other clients as well
 */
    class ClientToServerManager : public ConnectionManager<Response, Request> {

        //outgoing RSA initialized with server public key
        RSA2048 _rsa_out{};
        //incoming RSA initialized with user private key
        RSA2048 _rsa_in{};

        //future c-c managers
        std::map<std::string, ClientToClientManager> _userManagers;

    public:
        /**
         * @brief Initialize with keys from files
         *
         * @param pubkeyFilename rsa public key of the receiver filename path
         * @param privkeyFilename rsa private key of the owner filename path
         * @param pwd password to decrypt private key
         */
        ClientToServerManager(const std::string &pubkeyFilename,
                              const std::string &privkeyFilename, const std::string &pwd) {
            _rsa_out.loadPublicKey(pubkeyFilename);
            _rsa_in.loadPrivateKey(privkeyFilename, RSAKeyGen::getHexPwd(pwd), RSAKeyGen::getHexIv(pwd));
        }

        /**
         * @brief Initialize with public key from buffer
         *
         * @param publicKeyData buffer with public key in pem format (e.g. pem file loaded into buffer)
         * @param privkeyFilename rsa private key of the owner filename path
         * @param pwd password to decrypt private key
         */
        ClientToServerManager(const std::vector<unsigned char> &publicKeyData,
                              const std::string &privkeyFilename, const std::string &pwd) {
            _rsa_out.setPublicKey(publicKeyData);
            _rsa_in.loadPrivateKey(privkeyFilename, RSAKeyGen::getHexPwd(pwd), RSAKeyGen::getHexIv(pwd));
        }

        /**
        * @brief Initialize with public key from buffer
        *
        * @param publicKeyData buffer with public key in pem format (e.g. pem file loaded into buffer)
        * @param privkeyFilename rsa private key of the owner filename path
        * @param key aes key to decrypt private key
        * @param iv initialization vector for aes
        */
        ClientToServerManager(const std::vector<unsigned char> &publicKeyData,
                              const std::string &privkeyFilename, const std::string &key, const std::string &iv) {
            _rsa_out.setPublicKey(publicKeyData);
            _rsa_in.loadPrivateKey(privkeyFilename, key, iv);
        }


        Response parseIncoming(std::stringstream &&data) override {
            Response response;
            //data.header.messageNumber = _counter.
            if (_established) {
                //1) process head
                std::stringstream headIvStream = nBytesFromStream(data,
                                                                  AESGCM::iv_size * 2); //in hex string - 2x length
                std::stringstream headStream = nBytesFromStream(data, HEADER_ENCRYPTED_SIZE);
                std::stringstream headDecrypted;
                _gcm.setIv(headIvStream.str());
                headIvStream.seekg(0, std::ios::beg);
                _gcm.decryptWithAd(headStream, headIvStream, headDecrypted);

                //2) process body (future: will do only if head contains data for server)
                std::stringstream bodyIvStream = nBytesFromStream(data, AESGCM::iv_size * 2);
                std::stringstream bodyStream = nBytesFromStream(data, getSize(data));
                std::stringstream bodyDecrypted;
                _gcm.setIv(bodyIvStream.str());
                bodyIvStream.seekg(0, std::ios::beg);
                _gcm.decryptWithAd(bodyStream, bodyIvStream, bodyDecrypted);

                //3) build request
                std::vector<unsigned char> head(sizeof(Request::Header));
                read_n(headDecrypted, head.data(), head.size());
                response.header = Response::Header::deserialize(head);
                //will pass only encrypted payload if not for server to read
                response.payload.resize(getSize(bodyDecrypted));
                read_n(bodyDecrypted, response.payload.data(), response.payload.size());
            } else {
                //does not ensure integrity, results in connection failure as we're sending session key
                std::vector<unsigned char> header = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
                std::vector<unsigned char> body = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
                read_n(data, header.data(), header.size());
                read_n(data, body.data(), body.size());

                header = _rsa_in.decrypt(header);
                body = _rsa_in.decrypt(body);

                response.header = std::move(Response::Header::deserialize(header));
                response.payload = std::move(body);
            }
            return response;
        }

        std::stringstream parseOutgoing(const Request &data) override {
            std::stringstream result{};
            //data.header.messageNumber = _counter.
            if (_established) {
                std::stringstream body;
                write_n(body, data.payload);

                std::vector<unsigned char> head_data = data.header.serialize();
                std::stringstream head;
                write_n(head, head_data);

                //1) encrypt head
                std::string headIv = to_hex(_random.get(AESGCM::iv_size));
                std::istringstream headIvStream{headIv};
                std::stringstream headEncrypted;
                _gcm.setIv(headIv);
                write_n(result, headIv);
                _gcm.encryptWithAd(head, headIvStream, result);

                //2) encrypt body
                std::string bodyIv = to_hex(_random.get(AESGCM::iv_size));
                std::istringstream bodyIvStream{bodyIv};
                std::stringstream bodyEncrypted;
                _gcm.setIv(bodyIv);
                write_n(result, bodyIv);
                _gcm.encryptWithAd(body, bodyIvStream, result);
                bodyEncrypted.seekg(0, std::ios::beg);
                bodyIvStream.seekg(0, std::ios::beg);
            } else {
                //does not ensure integrity, results in connection failure as we're sending session key
                write_n(result, _rsa_out.encrypt(data.header.serialize()));
                write_n(result, _rsa_out.encrypt(data.payload));
            }
            result.seekg(0, std::ios::beg);
            return result;
        }

    private:
        //in future: will get connection from _userManagers and encrypts
        // message body with different approach
        /*std::vector<unsigned char> getUserInput()  = 0;*/

    };


/**
 * Class that is meant to parse only with server private key - incoming registration & request
 */
    class GenericServerManager {
        RSA2048 _rsa_in{};

    public:
        GenericServerManager(const std::string &privkeyFilename, const std::string &key, const std::string& iv) {
            _rsa_in.loadPrivateKey(privkeyFilename, key, iv);
        }


        Request parseIncoming(std::stringstream &&data) {
            Request request;
            std::vector<unsigned char> header = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
            std::vector<unsigned char> body = std::vector<unsigned char>(RSA2048::BLOCK_SIZE_OAEP);
            read_n(data, header.data(), header.size());
            read_n(data, body.data(), body.size());

            header = _rsa_in.decrypt(header);
            body = _rsa_in.decrypt(body);

            request.header = std::move(Request::Header::deserialize(header));
            request.payload = std::move(body);

            return request;
        }
    };

/**
 * Server side implementation with connection to one client at time
 * server always knows the session key as it is forwarded in auth / registration
 */
    class ServerToClientManager : public ConnectionManager<Request, Response> {
    public:
        explicit ServerToClientManager(const std::string &sessionKey) {
            openSecureChannel(sessionKey);
        }

        Request parseIncoming(std::stringstream &&data) override {
            Request request;
            //data.header.messageNumber = _counter.

            //1) process head
            std::stringstream headIvStream = nBytesFromStream(data, AESGCM::iv_size * 2); //in hex string - 2x length
            std::stringstream headStream = nBytesFromStream(data, HEADER_ENCRYPTED_SIZE);
            std::stringstream headDecrypted;
            _gcm.setIv(headIvStream.str());
            headIvStream.seekg(0, std::ios::beg);
            _gcm.decryptWithAd(headStream, headIvStream, headDecrypted);

            //2) process body (future: will do only if head contains data for server)
            std::stringstream bodyIvStream = nBytesFromStream(data, AESGCM::iv_size * 2);
            std::stringstream bodyStream = nBytesFromStream(data, getSize(data));
            std::stringstream bodyDecrypted;
            _gcm.setIv(bodyIvStream.str());
            bodyIvStream.seekg(0, std::ios::beg);
            _gcm.decryptWithAd(bodyStream, bodyIvStream, bodyDecrypted);

            //3) build request
            std::vector<unsigned char> head(sizeof(Request::Header));
            read_n(headDecrypted, head.data(), head.size());
            request.header = Request::Header::deserialize(head);
            //will pass only encrypted payload if not for server to read
            request.payload.resize(getSize(bodyDecrypted));
            read_n(bodyDecrypted, request.payload.data(), request.payload.size());

            return request;
        }

        std::stringstream parseOutgoing(const Response &data) override {
            std::stringstream result{};
            //data.header.messageNumber = _counter.

            std::stringstream body;
            write_n(body, data.payload);

            std::vector<unsigned char> head_data = data.header.serialize();
            std::stringstream head;
            write_n(head, head_data);

            //1) encrypt head
            std::string headIv = to_hex(_random.get(AESGCM::iv_size));
            std::istringstream headIvStream{headIv};
            std::stringstream headEncrypted;
            _gcm.setIv(headIv);
            write_n(result, headIv);
            _gcm.encryptWithAd(head, headIvStream, result);

            //2) encrypt body
            std::string bodyIv = to_hex(_random.get(AESGCM::iv_size));
            std::istringstream bodyIvStream{bodyIv};
            std::stringstream bodyEncrypted;
            _gcm.setIv(bodyIv);
            write_n(result, bodyIv);
            _gcm.encryptWithAd(body, bodyIvStream, result);
            bodyEncrypted.seekg(0, std::ios::beg);
            bodyIvStream.seekg(0, std::ios::beg);

            result.seekg(0, std::ios::beg);
            return result;
        }
    };

}

#endif //HELLOWORLD_SHARED_CONNECTIONMANAGER_H_
