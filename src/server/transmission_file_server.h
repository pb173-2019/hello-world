/**
 * @file transmission_file_server.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager implementation
 *          temporary testing solution
 *
 * @version 0.1
 * @date 21. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
#define HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_

#include <fstream>
#include <sstream>
#include <set>
#include <cstring>

#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"




namespace helloworld {

/**
* TCP version will handle id generating
*/
class ServerFiles : public ServerTransmissionManager {

    Base64 _base64;
    std::set<std::string> _files;

public:
    explicit ServerFiles(Callable<void, bool, const std::string&, std::stringstream&&>* callback) :
                         ServerTransmissionManager(callback) {
        //we put there the super class method, which is overridden (type error otherwise)
        Network::setServer(&ServerTransmissionManager::receive, this);
    };

    // Copying is not available
    ServerFiles(const ServerFiles &other) = delete;

    ServerFiles &operator=(const ServerFiles &other) = delete;

    ~ServerFiles() override {
        //testing - delete any .tcp files
        std::string leftovers = getFile(".tcp");
        while (!leftovers.empty()) {
            remove(leftovers.c_str());
            leftovers = getFile(".tcp");
        }
        Network::setServer(nullptr, nullptr);
    };

    void send(const std::string& usrname, std::iostream &data) override {
        data.seekg(0, std::ios::beg);

        std::ofstream send{usrname + "-response.tcp", std::ios::binary | std::ios::out};
        if (!send) {
            throw Error("Transmission failed.\n");
        }
        //saves into .tcp file
        _base64.fromStream(data, send);
        //notifies the user (static callback socket mock)
        send.close();
        Network::sendToUser(usrname);
    }

    void receive() override {
        std::string incoming = getFile(".tcp");
        std::ifstream received{incoming, std::ios::binary | std::ios::in};
        if (!received) {
            return;
        }

        std::stringstream result{};
        _base64.toStream(received, result);
        std::string name = incoming.substr(0, incoming.size() - 4);
        result.seekg(0, std::ios::beg);

        received.close();
        if (remove(incoming.c_str()) != 0) {
            throw Error("Could not finish transmission.\n");
        }

        Callable<void, bool, const std::string&, std::stringstream&&>::call(callback, exists(name),
                name, std::move(result));
    }

    /**
     * Mark some connection as opened
     * @param connection
     */
    void registerConnection(const std::string& username) override {
        if (username.empty())
            return;
        bool inserted = _files.emplace(username).second;
        if (!inserted) {
            throw Error("Could not register existing connection.");
        }
    }

    /**
     * Release connection
     * @param connection
     */
    void removeConnection(const std::string& username) override {
        _files.erase(username);
    }

    /**
     * Check filename for its connection
     * @param filename name to check
     * @return 0 if no connection found, otherwise >0
     */
    bool exists(const std::string& filename) {
        for (auto& item : _files) {
            if (item == filename) {
                return true;
            }
        }
        return false;
    }

    const std::set<std::string>& getOpenConnections() override {
        return _files;
    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
