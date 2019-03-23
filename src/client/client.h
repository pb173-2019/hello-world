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

#include <string>
#include <vector>
#include <memory>

#include "connection.h"
#include "secure_channel.h"
#include "transmission_file_client.h"
#include "../shared/request.h"
#include "../shared/user_data.h"

namespace helloworld {

class Client : public Callable<void, std::stringstream &&> {
    // specific connection
    //maybe use server approach - could have multiple user-user connections?
    //holds many connections to many users virtually (only remembers session data)
    //but physically is connected only to server




    Connection _connection{""};

public:
    Client();

    /**
    * @brief This function is called when transmission manager discovers new
    *        incoming request
    *
    * @param data decoded data, ready to process (if "", use user private key to do challenge)
    */
    void callback(std::stringstream &&data) override {
        Response reponse;

        if (_isConnected) {
            //todo parse challenge and set _isConnected as true
        } else {
            //todo parse response
        }
        // do something with response
    }

    /**
     * @brief Connect user to the server with given info.
     *
     * @param username name of user
     * @param password password of user
     */
    void login(const std::string &username, const std::string &password);

    /**
     * @brief Log out the user from server.
     */
    void logout();

    /**
     * @brief Send request to the server to register new user
     *
     * 1) generate rsa key
     * 2) generate 16 bytes of random chars,  and save into file named username_salt.txt
     * 3)
     *
     * @param username  name of user
     * @param password password of user
     */
    void createAccount(const std::string &username, const std::string &password);

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
    //TESTING PURPOSE METHODS SECTION
    //

    //check for request, in future: either will run in thread later as listening
    //or gets notified by TCP
    void getRequest() {
        _transmission->receive();
    };

private:
    bool _isConnected = false;
    std::unique_ptr<UserTransmissionManager> _transmission;
    std::string _username;

};

}  // namespace helloworld

#endif  // HELLOWORLD_CLIENT_CLIENT_H_
