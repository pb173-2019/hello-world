/**
 * @file transmission.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager takes care of stream tranmission
 *  - notifies server about new connection request
 *  - generates ids for connection
 *  - uses encoder
 *
 * Network class takes care of the inner calls between server & users
 *
 * @version 0.1
 * @date 21. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_TRANSMISSION_H_
#define HELLOWORLD_SHARED_TRANSMISSION_H_

#include <string>
#include <set>
#include <map>
#include <fstream>

#include "utils.h"
#include "serializable_error.h"

namespace helloworld {

class ServerTransmissionManager {
protected:
    /**
     * Function that can handle receive() output
     */
    Callable<void, bool, const std::string &, std::stringstream &&> *callback;

public:
    explicit ServerTransmissionManager(Callable<void, bool,
            const std::string &, std::stringstream &&> *callback) : callback(callback) {
        if (callback == nullptr)
            throw Error("Null not allowed.");
    };

    // Copying is not available
    ServerTransmissionManager(const ServerTransmissionManager &other) = delete;

    ServerTransmissionManager &operator=(const ServerTransmissionManager &other) = delete;

    virtual ~ServerTransmissionManager() = default;

    /**
     * @brief Send data
     *
     * @param usrname user name as connection id
     * @param data data as iostream to process
     */
    virtual void send(const std::string &usrname, std::iostream &data) = 0;

    /**
     * @brief Receive request / response depending on side
     *        in TCP, this method is waiting for any incoming request / reponse
     *        uses callback to forward unsigned long, std::stringstream
     */
    virtual void receive() = 0;

    /**
   * Mark some connection as opened
   * @param connection
   */
    virtual void registerConnection(const std::string &usrname) = 0;

    /**
     * Release connection
     * @param connection
     */
    virtual void removeConnection(const std::string &usrname) = 0;

    /**
     * Get online user list
     */
    virtual const std::set<std::string> &getOpenConnections() = 0;


};

class UserTransmissionManager {
protected:
    /**
     * Function that can handle receive() output
     */
    Callable<void, std::stringstream &&> *callback;
    std::string username;

public:
    explicit UserTransmissionManager(Callable<void, std::stringstream &&> *callback,
                                     std::string username) : callback(callback), username(std::move(username)) {
        if (callback == nullptr)
            throw Error("Null not allowed.");
    };

    // Copying is not available
    UserTransmissionManager(const UserTransmissionManager &other) = delete;

    UserTransmissionManager &operator=(const UserTransmissionManager &other) = delete;

    virtual ~UserTransmissionManager() = default;

    /**
     * @brief Send data
     *
     * @param data data as iostream to process
     */
    virtual void send(std::iostream &data) = 0;

    /**
     * @brief Receive request / response depending on side
     *        in TCP, this method is waiting for any incoming request / reponse
     *        uses callback to forward unsigned long, std::stringstream
     */
    virtual void receive() = 0;
};

// a bit ugly way to notify server that the "socket" has arrived
using server_socket = void (ServerTransmissionManager::*)();
using client_socket = void (UserTransmissionManager::*)();

class Network {
    static server_socket server_callback;
    static ServerTransmissionManager* server_instance;
    static std::map<std::string, std::pair<client_socket, UserTransmissionManager*>> connection_callbacks;
    static std::vector<std::pair<std::string, std::vector<unsigned char>>> delayed;

    static bool enabled;
    static bool problem;

public:
    /*
     * Switch the network feature on/off
     */
    static void setEnabled(bool isEnabled) {
        enabled = isEnabled;
    }

    /*
     * Switch delaying network messages on/off
     */
    static void setProblematic(bool isProblematic) {
        problem = isProblematic;
    }

    /*
     * Set server instance's transmission manager to receive messages
     * done automatically in constructor
     */
    static void setServer(server_socket serverCallback, ServerTransmissionManager* server) {
        server_callback = serverCallback;
        server_instance = server;
    }

    /*
     * Add user's connection manager to receive data from server
     * done automatically in constructor
     */
    static void addConnection(const std::string &username, std::pair<client_socket, UserTransmissionManager*> client) {
        connection_callbacks.emplace(username, client);
    }

    /*
     * Remove user's callback
     * done automatically in destructor
     */
    static void releaseConnection(const std::string &username) {
        connection_callbacks.erase(username);
    }

    /*
     * Release last delayed message (stack)
     */
    static void release();

    /*
     * Release all delayed messages (stack)
     */
    static void releaseAll() {
        while (!delayed.empty()) {
            release();
        }
    }

    /*
     * Return current blocked message sender (<name>.tcp) format
     */
    static const std::string* getBlockedMsgSender() {
        if (delayed.empty())
            return nullptr;
        return &(delayed.end() - 1)->first;
    }

    /*
     * Discard last delayed message (stack)
     */
    static void discard();

    /*
     * Send automatically message to server
     * doesn't work if not enabled
     * done automatically in transmission manager
     */
    static void sendToServer();

    /*
     * Send automatically message to user
     * doesn't work if not enabled
     * done automatically in transmission manager
     */
    static void sendToUser(const std::string &username);
};


} //namespace helloworld

#endif //HELLOWORLD_TRANSMISSION_H
