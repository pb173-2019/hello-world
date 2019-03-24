/**
 * @file server.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Server interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_SERVER_H_
#define HELLOWORLD_SERVER_SERVER_H_

#include <map>
#include <memory>
#include <string>

#include "../shared/random.h"
#include "../shared/request.h"
#include "../shared/rsa_2048.h"
#include "../shared/connection_manager.h"
#include "transmission_file_server.h"
#include "database.h"

namespace helloworld {

/**
 * @brief Stores information about newly registered user,
 * creates -to be- connection manager and stores
 * his key verification challenge. When succesfull,
 * the manager is moved into _connections
 */
struct Challenge {
    UserData userData;
    std::unique_ptr<ServerToClientManager> manager;
    std::vector<unsigned char> secret;

    Challenge(UserData userData, std::vector<unsigned char> secret, const std::string &sessionKey)
            : userData(std::move(userData)), secret(std::move(secret)),
              manager(std::make_unique<ServerToClientManager>(sessionKey)) {}
};


// not needed for now

///**
// * @brief Mapping between socket connections and user info.
// *
// */
//struct SocketInfo {
//    std::string username;
//    ServerToClientManager manager;
//
//    SocketInfo(std::string username, const std::vector<unsigned char>& clientPublicKeyData,
//            const std::string& serverPrivKey) :
//            username(std::move(username)),
//            manager(clientPublicKeyData, serverPrivKey,
//                    "323994cfb9da285a5d9642e1759b224a",
//                    "2b7e151628aed2a6abf7158809cf4f3c") {}
//};

class Server : public Callable<void, const std::string &, std::stringstream &&> {
    static const size_t CHALLENGE_SECRET_LENGTH = 256;

public:
    Server();

    /**
     * @brief This function is called when transmission manager discovers new
     *        incoming request
     *
     * @param username username of incoming connection, 0 if not opened (e.g. authentication needed)
     * @param data decoded data, ready to process (if 0, use server key to encrypt)
     */
    void callback(const std::string &username, std::stringstream &&data) override {
        Request request;
        if (username.empty()) {
            request = _genericManager.parseIncoming(std::move(data));
        } else {
            auto existing = _connections.find(username);
            if (existing == _connections.end()) {
                auto pending = _requestsToConnect.find(username);
                if (pending == _requestsToConnect.end())
                    throw Error("No such connection available.");

                request = pending->second->manager->parseIncoming(std::move(data));
            } else {
                request = existing->second->parseIncoming(std::move(data));
            }
        }
        handleUserRequest(request);
    }

    /**
     * @brief Handle incoming request
     *
     * @param request request from not connected user
     * @return Response response data
     */
    Response handleUserRequest(const Request &request);


    /**
     * @brief Handle incoming request for system on system port
     *
     * @return uint32_t connection id
     */
    uint32_t establishConnection();

    /**
     * @brief Terminate connection
     *
     * @param cid connection id
     */
    void terminateConnection(uint32_t cid);


    //
    //TESTING PURPOSE METHODS SECTION
    //

    //clear database to start from new
    void dropDatabase();

    //check users present in db
    std::vector<std::string> getUsers();

    //check for request, in future: either will run in thread later as listening
    //or gets notified by TCP
    void getRequest() {
        _transmission->receive();
    };

private:
    Random _random;
    GenericServerManager _genericManager;
    std::map<std::string, std::unique_ptr<ServerToClientManager>> _connections;
    std::map<std::string, std::unique_ptr<Challenge>> _requestsToConnect;
    std::unique_ptr<Database> _database;
    std::unique_ptr<ServerTransmissionManager> _transmission;

    /**
     * @brief Register new user and respond with public key verification
     * challenge. Request is received by assymetric cryptography using
     * the server's public key.
     *
     * @param connectionId temporarily removed connection id
     * @param request request from client
     * @return Response challenge response
     */
    Response registerUser(const Request &request);

    /**
     * @brief Check correctness of client's public key and register
     * him into the database.
     *
     * @param connectionId temporarily removed connection id
     * @param request request from client
     * @return Response OK if user was registered
     */
    Response completeUserRegistration(const Request &request);

    /**
     * @brief Authenticate user by his knowledge of private key.
     *
     * @param connectionId temporarily removed connection id
     * @param request request from client
     * @return Response OK challenge response
     */
    Response authenticateUser(const Request &request);

    /**
     * @brief Check correctness of client's public key and log him in.
     *
     * @param connectionId temporarily removed connection id
     * @param request request from client
     * @return Response OK response if user was registered
     */
    Response completeUserAuthentication(const Request &request);

    /**
     * @brief Get online user list
     *
     * @param request request from the client
     * @return response containing list of online users
     */
    Response getOnline(const Request &request);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_SERVER_H_
