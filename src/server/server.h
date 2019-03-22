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
#include "../shared/transmission_file.h"
#include "database.h"

namespace helloworld {

/**
 * @brief Stores information about newly registered user and
 * his key verification challenge.
 */
    struct Challenge {
        UserData userData;
        std::vector<unsigned char> secret;

        Challenge(UserData userData, std::vector<unsigned char> secret)
                : userData(std::move(userData)), secret(std::move(secret)) {}
    };

/**
 * @brief Mapping between socket connections and user info.
 *
 */
    struct SocketInfo {
        std::vector<unsigned char> sessionKey;
        std::string username;
    };

    class Server : public Callable<void, unsigned long, std::stringstream&&> {
        static const size_t CHALLENGE_SECRET_LENGTH = 256;

    public:
        Server();

        /**
         * @brief This function is called when transmission manager discovers new
         *        incoming request
         *
         * @param id id of incoming connection, 0 if not opened (e.g. authentication needed)
         * @param data decoded data, ready to process (if 0, use server key to encrypt)
         */
        void callback(unsigned long id, std::stringstream&& data) override {
            if (id == 0) {
                //todo parse data using private key of the server
                Request request;
                handleUserRequest(request);
            } else {
                //todo parse data using session manager
                Request request;
                handleUserRequest(id, request);
            }
        }

        /**
         * @brief Handle incoming request on new port
         *
         * @param request request from not connected user
         * @return Response response data
         */
        Response handleUserRequest(const Request &request);

        /**
         * @brief Handle incoming request on user port
         *
         * @param connectionId connection id
         * @param request request from user
         * @return Response response data
         */
        Response handleUserRequest(unsigned long connectionId, const Request &request);

        /**
         * @brief Handle incoming request for system on system port
         *
         * @return unsigned long connection id
         */
        unsigned long establishConnection();

        /**
         * @brief Terminate connection
         *
         * @param cid connection id
         */
        void terminateConnection(unsigned long cid);

        /**
         * @brief Set session key for a specific connection.
         *
         * @param connectionId connection id
         * @param sessionKey symmetric cryptography key
         */
        void setSessionKey(unsigned long connectionId, std::vector<unsigned char> sessionKey);

        /**
         * @brief Drop the server database
         *
         */
        void dropDatabase();

        std::vector<std::string> getUsers();

    private:
        Random _random;
        std::map<unsigned long, SocketInfo> _connections;
        std::map<unsigned long, Challenge> _authentications;
        std::map<std::string, Challenge> _registrations;
        std::unique_ptr<Database> _database;
        std::unique_ptr<TransmissionManager> _transmission;
        RSA2048 _rsa;

        /**
         * @brief Register new user and respond with public key verification
         * challenge. Request is received by assymetric cryptography using
         * the server's public key.
         *
         * @param connectionId connection id
         * @param request request from client
         * @return Response challenge response
         */
        Response registerUser(unsigned long connectionId, const Request &request);

        /**
         * @brief Check correctness of client's public key and register
         * him into the database.
         *
         * @param connectionId connection id
         * @param request request from client
         * @return Response OK if user was registered
         */
        Response completeUserRegistration(unsigned long connectionId, const Request &request);

        /**
         * @brief Authenticate user by his knowledge of private key.
         *
         * @param connectionId connection id
         * @param request request from client
         * @return Response OK challenge response
         */
        Response authenticateUser(unsigned long connectionId, const Request &request);

        /**
         * @brief Check correctness of client's public key and log him in.
         *
         * @param connectionId connection id
         * @param request request from client
         * @return Response OK response if user was registered
         */
        Response completeUserAuthentication(unsigned long connectionId,
                                            const Request &request);
    };

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_SERVER_H_
