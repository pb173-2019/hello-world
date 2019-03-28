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
#include "../shared/request_response.h"
#include "../shared/rsa_2048.h"
#include "../shared/connection_manager.h"
#include "../shared/requests.h"
#include "transmission_file_server.h"
#include "database_server.h"

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


class Server : public Callable<void, bool, const std::string &, std::stringstream &&> {
    //rsa maximum encryption length of 126 bytes
    static const size_t CHALLENGE_SECRET_LENGTH = 126;

public:
    Server();

    /**
     * @brief This function is called when transmission manager discovers new
     *        incoming request
     *
     * @param username username of incoming connection, 0 if not opened (e.g. authentication needed)
     * @param data decoded data, ready to process (if 0, use server key to encrypt)
     */
    void callback(bool hasSessionKey, const std::string &username, std::stringstream &&data) override {
        Request request;
        Response response;
        try {
            if (!hasSessionKey) {
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
        } catch (Error &ex) {
            std::cerr << ex.what() << std::endl;
            sendReponse(username,
                    {{Response::Type::GENERIC_SERVER_ERROR, request.header.messageNumber,
                      request.header.userId}, ex.serialize()}, getManagerPtr(username, true));
        } catch (std::exception& generic) {
            std::cerr << generic.what() << std::endl;
            sendReponse(username, {{Response::Type::GENERIC_SERVER_ERROR, request.header.messageNumber,
                                    request.header.userId}, from_string(generic.what()) },
                                            getManagerPtr(username, true));
        }
    }

    /**
     * @brief Handle incoming request
     *
     * @param request request from not connected user
     * @return Response response data (testing purposes)
     */
    Response handleUserRequest(const Request &request);


    //
    //TESTING PURPOSE METHODS SECTION
    //

    //clear database to start from new
    void dropDatabase();

    //visible because of testing, private otherwise
    std::vector<std::string> getUsers(const std::string& query);

    //check for request, in future: either will run in thread later as listening
    //or gets notified by TCP
    void getRequest() {
        _transmission->receive();
    };

    /**
    * @brief Logout user implementation
    * testing: visible as public
    *
    * @param name name to log out
    */
    void logout(const std::string& name);

private:
    Random _random;
    GenericServerManager _genericManager;
    std::map<std::string, std::unique_ptr<ServerToClientManager>> _connections;
    std::map<std::string, std::unique_ptr<Challenge>> _requestsToConnect;
    std::unique_ptr<ServerDatabase> _database;
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
     * @brief Verify the signature and authenticate user
     *
     * @param connectionId temporarily removed connection id
     * @param newUser true if user just registered (will insert database info)
     * @param request request from client
     * @return Response OK if user was registered
     */
    Response completeAuthentication(const Request &request, bool newUser);

    /**
     * @brief Authenticate user by his knowledge of private key.
     *
     * @param connectionId temporarily removed connection id
     * @param request request from client
     * @return Response OK challenge response
     */
    Response authenticateUser(const Request &request);

    /**
     * @brief Get online user list
     *
     * @param request request from the client
     * @return response containing list of online users
     */
    Response getOnline(const Request &request);

    /**
     * @brief Delete account from server
     *
     * @param request request from the client
     * @return Response OK response if user was deleted
     */
    Response deleteAccount(const Request &request);

    /**
     * @brief Logout user
     *
     * @param request request from the client
     * @return Response OK response if user was logged out
     */
    Response logOut(const Request &request);

    /**
     * @brief Search database of users
     * @param request request containing name of the issuer
     * @return list of users from database by query given in request
     */
    Response findUsers(const Request &request);

    /**
     * Send reponse to user with manager
     *
     * @param username username to send the response to
     * @param response response to parse
     * @param manager manager to use or nullptr - the server will return generic error
     */
    void sendReponse(const std::string& username, const Response &response, ServerToClientManager* manager);

    /**
     * Send response to user without manager (e.g. auth fails)
     *
     * @param username username to send the response to
     * @param response response to parse
     * @param sessionKey session key to use to encrypt reponse, or empty string - the server will return generic error
     */
    void sendReponse(const std::string& username, const Response &response, const std::string& sessionKey);

    /**
     *
     * @param username manager to the user
     * @param trusted true if manager is supposed to be in _connections
     * @return ptr to user manager, nullptr if failed
     */
    ServerToClientManager* getManagerPtr(const std::string& username,  bool trusted);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_SERVER_H_
