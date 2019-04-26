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
#include <functional>
#include <string>
#include <QtCore/QObject>
#include <QReadWriteLock>

#include "../shared/random.h"
#include "../shared/request_response.h"
#include "../shared/rsa_2048.h"
#include "../shared/connection_manager.h"
#include "../shared/requests.h"
#include "../shared/transmission.h"
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


class Server : public QObject, public Callable<void, bool, const std::string &, std::stringstream &&> {
Q_OBJECT
    static bool _test;
    //rsa maximum encryption length of 126 bytes
    static const size_t CHALLENGE_SECRET_LENGTH = 126;

    std::function<void(const std::string&)> log{[](const std::string&){}};
public:
    Server();

    ServerTransmissionManager *getTransmisionManger() {
        if (_transmission == nullptr) return nullptr;
        return _transmission.get();
    }

    void setTransmissionManager(std::unique_ptr<ServerTransmissionManager>&& ptr) {
        _transmission = std::move(ptr);
    }

    void setLogging(const std::function<void(const std::string&)> &foo) {
        log = foo;
    }

    static void setTest(bool isTesting) {
        _test = isTesting;
    }
    /**
     * @brief This function is called when transmission manager discovers new
     *        incoming request
     *
     * @param hasSessionKey false if first connection (e.g. session key not established) maybe not needed
     *        (use empty name)
     * @param username username of incoming connection, empty if not opened (e.g. authentication needed)
     * @param data decoded data, ready to process (if username empty, use server key to encrypt)
     */
    void callback(bool hasSessionKey, const std::string &username, std::stringstream &&data) override {
        Request request;
        Response response;
        try {
            if (!hasSessionKey || username.empty()) {
                request = _genericManager.parseIncoming(std::move(data));
            } else {
                QReadLocker lock(&_connectionLock);
                auto existing = _connections.find(username);
                if (existing == _connections.end()) {
                    auto pending = _requestsToConnect.find(username);
                    if (pending == _requestsToConnect.end())
                        throw Error("No such connection available.");

                    request = pending->second.first->manager->parseIncoming(std::move(data));
                } else {
                    request = existing->second->parseIncoming(std::move(data));
                }
            }

            handleUserRequest(request);
        } catch (Error &ex) {
            log(std::string() + "Error: " + ex.what());
            QReadLocker lock(&_connectionLock);
            sendReponse(username,
                        {{Response::Type::GENERIC_SERVER_ERROR, request.header.userId}, ex.serialize()},
                        getManagerPtr(username, true));
        } catch (std::exception &generic) {
            log(std::string() + "Generic error: " + generic.what());
            QReadLocker lock(&_connectionLock);
            sendReponse(username, {{Response::Type::GENERIC_SERVER_ERROR, request.header.userId},
                                   from_string(generic.what())}, getManagerPtr(username, true));
        } catch (...) {
            //__cxa_exception_type() does not work with MSVC
            std::exception_ptr p = std::current_exception();
            log(std::string() + "Fatal error: " /*+ (p ? p.__cxa_exception_type()->name() : "unknown")*/);
            QReadLocker lock(&_connectionLock);
            sendReponse(username, {{Response::Type::GENERIC_SERVER_ERROR, request.header.userId},
                                   from_string(/*p ? p.__cxa_exception_type()->name() : */"unknown error")},
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
    }
    
    //to get to database
    const ServerDatabase& getDatabase() {
        return *_database;
    }

    //delete connection id (username) to treat new request as new connection
    void simulateNewChannel(const std::string& old) {
        _transmission->removeConnection(old);
    }
    void restoreOldChannel(const std::string& old) {
        _transmission->registerConnection(old);
    }

private:
    Random _random;
    GenericServerManager _genericManager;
    QReadWriteLock _connectionLock;
    std::map<std::string, std::unique_ptr<ServerToClientManager>> _connections;
    QReadWriteLock _requestLock;
    std::map<std::string, std::pair<std::unique_ptr<Challenge>, bool> > _requestsToConnect;

    std::unique_ptr<ServerDatabase> _database;
    std::unique_ptr<ServerTransmissionManager> _transmission;

//for testing -> public    
public:
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
     * @param request request from client
     * @return Response OK if user was registered
     */
    Response completeAuthentication(const Request &request);

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
     * @brief Called to forward message
     *
     * @param request request containing data to send
     * @return Response OK response if stored succesfully
     */
    Response forward(const Request &request);

    /**
     * Uploads to the database new key bundle
     *
     * @param request request containing key bundle
     * @return OK if nothing needed, specific server response on event
     */
    Response updateKeyBundle(const Request &request);

    /**
     * Sends the key bundle to anyone who requests it
     * deletes the last key from one time keys if present
     *
     * @param request request containing receiver's id in header, instead of the user
     *        who requested it
     * @return bundled keys response
     */
    Response sendKeyBundle(const Request &request);

    /**
     * Request any new messages
     *
     * @param request request with user name & id
     * @return uses checkEvent()
     */
    Response checkIncoming(const Request &request);

    /**
     * @brief Logout user implementation
     *
     * @param name name to log out
     */
     void logout(const std::string& name);

    /**
     * @brief Called when OK reponse should be sent
     *        notifies user whether an event occurs that should user know
     *        (e.g. old keys, empty key pool)
     *
     * @param request to get message number & user id
     * @return OK if nothing needed, specific server response on event
     */
    Response checkEvent(uint32_t uid);

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

    public slots:
    void cleanAfterConenction(QString qname) {
        auto name = qname.toStdString();
        auto chalangeIt = _requestsToConnect.find(name);
        if (chalangeIt != _requestsToConnect.end())
            _requestsToConnect.erase(chalangeIt);

        auto connectionIt = _connections.find(name);
        if (connectionIt != _connections.end())
            _connections.erase(connectionIt);
        log("cleaning after: " + qname.toStdString());
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SERVER_SERVER_H_
