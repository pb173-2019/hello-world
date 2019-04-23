/**
 * @file client.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Client interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_CLIENT_H_
#define HELLOWORLD_CLIENT_CLIENT_H_

#include <memory>
#include <string>
#include <vector>
#include <QObject>

#include "../shared/X3DH.h"
#include "../shared/connection_manager.h"
#include "../shared/double_ratchet.h"
#include "../shared/request_response.h"
#include "../shared/requests.h"
#include "../shared/rsa_2048.h"
#include "../shared/user_data.h"
#include "../shared/transmission.h"

namespace helloworld {

class Client : public QObject, public Callable<void, std::stringstream &&> {
    static constexpr int SYMMETRIC_KEY_SIZE = 16;
    Q_OBJECT
public:
    Client(std::string username, const std::string &clientPrivKeyFilename,
           const std::string &password, QObject *parent = nullptr);


    UserTransmissionManager *getTransmisionManger() {
        return _transmission.get();
    }

    void setTransmissionManager(std::unique_ptr<UserTransmissionManager>&& ptr) {
        _transmission = std::move(ptr);
    }

    bool ready() {
        return _transmission
            && _transmission->status() == UserTransmissionManager::Status::OK;
    }

    const std::string& name() const {
        return _username;
    }
    /**
     * @brief This function is called when transmission manager discovers new
     *        incoming request
     *
     * @param data decoded data, ready to process (if "", use user private key
     * to do challenge)
     */
    void callback(std::stringstream &&data) override;

    /**
     * @brief Connect user to the server with given info.
     *
     * @param username name of user
     * @param password password of user
     */
    void login();

    /**
     * @brief Log out the user from server.
     */
    void logout();

    /**
     * @brief Send request to the server to register new user
     *
     * @param username  name of user
     * @param password password of user
     */
    void createAccount(const std::string &pubKeyFilename);

    /**
     * @brief Permanently deletes the user from server
     */
    void deleteAccount();

    /**
     * @brief Get user list based on given query
     *
     */
    void sendFindUsers(const std::string &name);

    /**
     * @brief Get online user list
     */
    void sendGetOnline();

    /**
     * @brief Returns the userlist requested in send*()
     */
    const std::map<uint32_t, std::string> &getUsers() const { return _userList; }
    std::map<uint32_t, std::string> &getUsers() { return _userList; }
    /**
     * @brief Just ask server whether messages available
     */
    void checkForMessages();

    /**
     * Send data to server
     * @param data data to send
     * @param keys
     */
    void sendKeysBundle();

    /**
     * Request key bundle for user with id given.
     * The id should be obtained in user-getting methods
     *
     * @param receiverId id of user that owns the bundle (message receiver)
     */
    void requestKeyBundle(uint32_t receiverId);

    /**
     * Send data to other user
     * decides whether to encrypt with double ratchet (e.g. session is runnung)
     * or request new key bundle & start session
     *
     * @param receiverId user id - the user that is supposed to receive the data
     * @param data data to send
     */
    void sendData(uint32_t receiverId, const std::vector<unsigned char> &data);

    /**
     * Send data to other user using X3Dh protocol
     * called on server response RECEIVER_BUNDLE which was invoked by sendData()
     *
     * @param response keys bundle of the receiver downloaded from server
     *          in header is the **receiver's id**, not senders
     * @param data data to send
     */
    void sendInitialMessage(const Response &response);

    /**
     * Receive data from user, decides whether treat as X3DH protocol or just
     * process using double ratchet
     *
     * @param response response obtained by user
     */
    void receiveData(const Response &response);

    /**
     * Get the message parsed by x3dh or ratchet
     * @return last message received
     */
    SendData& getMessage() { return _incomming; }


    //
    // TESTING PURPOSE METHODS SECTION
    //

    // check for request, in future: either will run in thread later as
    // listening or gets notified by TCP
    void getResponse() { _transmission->receive(); };

    uint32_t getId() { return _userId; }

private:
    const std::string _username;
    const std::string _password;
    uint32_t _userId = 0;

    // todo think of better way to get incomming message
    SendData _incomming;
    std::map<uint32_t, std::string> _userList;

    RSA2048 _rsa;
    std::unique_ptr<X3DH> _x3dh;
    std::unique_ptr<DoubleRatchet> _doubleRatchetConnection;
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::unique_ptr<ClientToServerManager> _connection = nullptr;

    /**
     * Generates new keyset and possibly moves the old set into
     * files that equals with filename to previous files except .old add-on
     *
     * @return new keyBundle for X3DH
     */
    KeyBundle<C25519> updateKeys();

    /**
     * Performs server challenge
     * @param secret secret to prove the identity over
     * @param type type of authentication (on registration / login)
     * @return request to server to verify the challenge sent in this request
     * payload
     */
    Request completeAuth(const std::vector<unsigned char> &secret,
                         Request::Type type);

    /**
     * Generic request sender
     * @param request request to send
     */
    void sendRequest(const Request &request);

    /**
     * Obtains UserList response and parses it
     * @param response response obtained on get-users like methods
     */
    void parseUsers(const Response &response);

    /**
     * Generic request sender, sends request with header only
     *
     * @param type request type
     */
    void sendGenericRequest(Request::Type type);

    /**
     * Archives the key file - reads keyFileName and saves into
     * keyFileName.old
     *
     * @param keyFileName filename to archive
     */
    void archiveKey(const std::string &keyFileName);
signals:
    void error(QString);
};

//separated from client as this is used as testing extension that deletes the *key, *pub, *old files
void ClientCleaner_Run();

}    // namespace helloworld

#endif    // HELLOWORLD_CLIENT_CLIENT_H_
