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

#include "../shared/connection_manager.h"
#include "../shared/request_response.h"
#include "../shared/user_data.h"
#include "../shared/rsa_2048.h"
#include "../shared/curve_25519.h"
#include "../shared/requests.h"
#include "secure_channel.h"
#include "transmission_file_client.h"

namespace helloworld {

//todo delete when implemented
class DoubleRatchet {
public:
    bool running() {
        return false;
    }
};

class Client : public Callable<void, std::stringstream &&> {
    static constexpr int SYMMETRIC_KEY_SIZE = 16;

   public:
    Client(std::string username, const std::string &serverPubKeyFilename,
           const std::string &clientPrivKeyFilename,
           const std::string &password);

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
    void createAccount(const std::string& pubKeyFilename);

    /**
     * @brief Permanently deletes the user from server
     */
    void deleteAccount();

    /**
     * @brief Get user list based on given query
     *
     */
    void sendFindUsers(const std::string &name); //todo return ids as well

    /**
     * @brief Get online user list
     */
    void sendGetOnline(); //todo return ids as well

    /**
     * Returns the userlist requested in send*()
     */
     const std::vector<std::string>& getUsers() {
        return _userList;
     }

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
     * @param userId
     */
    void requestKeyBundle(uint32_t userId);

    /**
     * Send data to other user
     * decides whether to encrypt with double ratchet (e.g. session is runnung)
     * or request new key bundle & start session
     *
     * @param receiverId user id - the user that is supposed to receive the data
     * @param data data to send
     */
    void sendData(uint32_t receiverId, const std::vector<unsigned char>& data);

    /**
     * Send data to other user using X3Dh protocol
     * called on server response RECEIVER_BUNDLE which was invoked by sendData()
     *
     * @param receiverId user id - the user that is supposed to receive the data
     * @param bundle keys bundle of the receiver
     * @param data data to send
     */
    void sendInitialMessage(uint32_t receiverId, const Response& bundle);


    //
    // TESTING PURPOSE METHODS SECTION
    //

    // check for request, in future: either will run in thread later as
    // listening or gets notified by TCP
    void getResponse() { _transmission->receive(); };

private:
    const std::string _username;
    const std::string _pwd;
    uint32_t _userId = 0;
    //todo config file with all constants
    const std::string _clientPubKeyFilename;
    //todo move to connection manager, now its only sent to manager anyway
    const std::string _sessionKey;
    std::unique_ptr<DoubleRatchet> _usersSession;
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::unique_ptr<ClientToServerManager> _connection = nullptr;
    std::vector<std::string> _userList;
    //todo config file
    const std::string _serverPubKey;
    std::string _password;

    RSA2048 _rsa;

    KeyBundle<C25519> updateKeys();

    Request completeAuth(const std::vector<unsigned char> &secret,
                         Request::Type type);
    void sendRequest(const Request &request);

    void parseUsers(const Response& response);

    void sendGenericRequest(Request::Type type);
};

}    // namespace helloworld

#endif    // HELLOWORLD_CLIENT_CLIENT_H_
