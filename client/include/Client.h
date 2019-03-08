//
// Created by horak_000 on 8. 3. 2019.
//

#ifndef WASSUP_CLIENT_H
#define WASSUP_CLIENT_H

#include "SecureChannel.h"

struct UserData {
    long id;
    std::string name;
};

class Client {

    //specific connection
    Connection connection;

public:

    /**
    * Connect user to the server with given info
    * @param username name of user
    * @param password password of user
    */
    void login(const std::string& username, const std::string& password);

    /**
     * Log out the user from server
     */
    void logout();

    /**
     * Sends request to the server to register new user
     * @param username name of user
     * @param password password of user
     */
    void createAccount(const std::string& username, const std::string& password);

    /**
     * Permanently deletes the user from server
     */
    void deleteAccount();

    /**
     * Get user list based on given query
     * @param nameQuery query to perform search
     * @return list of users matching the given query
     */
    std::vector<UserData> getUsers(const std::string& nameQuery);
};


#endif //WASSUP_CLIENT_H
