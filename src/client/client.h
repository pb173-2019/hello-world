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
#include "../shared/request.h"
#include "../shared/user_data.h"
#include "../shared/rsa_2048.h"
#include "../server/requests.h"
#include "connection.h"
#include "secure_channel.h"
#include "transmission_file_client.h"

namespace helloworld {

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
    // todo hint delete me
    // server response is always encrypted with session key, when
    // registered/logged in, initialize the _transmission with generated session
    // key
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
    // todo hint delete me
    // server response is always encrypted with session key, when
    // registered/logged in, initialize the _transmission with generated session
    // key
    void createAccount(const std::string& pubKeyFilename);

    /**
     * @brief Permanently deletes the user from server
     */
    void deleteAccount();

    /**
     * @brief Get user list based on given query
     *
     * @param query query to perform search
     * @return std::vector<UserData> list of users matching the given query
     */
    std::vector<UserData> getUsers(const std::string &query);

    //
    // TESTING PURPOSE METHODS SECTION
    //

    // check for request, in future: either will run in thread later as
    // listening or gets notified by TCP
    void getRequest() { _transmission->receive(); };

   private:
    const std::string _username;
    const std::string _clientPubKeyFilename;
    const std::string _sessionKey;
    std::unique_ptr<UserTransmissionManager> _transmission;
    ClientToServerManager _connection;
    RSA2048 _rsa;

    Request completeAuth(const std::vector<unsigned char> &secret,
                         Request::Type type);
    void sendRequest(const Request &request);
};

}    // namespace helloworld

#endif    // HELLOWORLD_CLIENT_CLIENT_H_
