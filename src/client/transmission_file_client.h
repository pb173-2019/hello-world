/**
 * @file transmission_file_client.h
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

#ifndef HELLOWORLD_SHARED_TRANSMISSION_FILE_CLIENT_H_
#define HELLOWORLD_SHARED_TRANSMISSION_FILE_CLIENT_H_

#include <fstream>
#include <sstream>
#include <set>
#include <cstring>
#include <ctime>

#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"

namespace helloworld {

/**
* TCP version will handle id generating
*/
class ClientFiles : public UserTransmissionManager {

    Base64 _base64;
    std::string unique_identifier;

public:
    explicit ClientFiles(Callable<void, std::stringstream &&> *callback,
                         std::string username) : UserTransmissionManager(callback, std::move(username), OK) {
        //unique_identifier = username + std::to_string(std::time(nullptr));
        //username is moved, so we have to use the inner value
        Network::addConnection(this->username, std::make_pair(&UserTransmissionManager::receive, this));
    };

    // Copying is not available
    ClientFiles(const ClientFiles &other) = delete;

    ClientFiles &operator=(const ClientFiles &other) = delete;

    ~ClientFiles() override {
        Network::releaseConnection(username);
    }

    void send(std::iostream &data) override {
        data.seekg(0, std::ios::beg);

        std::ofstream send{username + ".tcp", std::ios::binary | std::ios::out};
        if (!send) {
            throw Error("Transmission failed.\n");
        }
        _base64.fromStream(data, send);
        send.close();
        Network::sendToServer();
    }

    void receive() override {
        try {
            std::ifstream received{username + "-response.tcp", std::ios::binary | std::ios::in};
            if (!received) {
                return;
            }

            std::stringstream result{};
            _base64.toStream(received, result);
            received.close();
            if (remove((username + "-response.tcp").c_str()) != 0) {
                throw Error("Could not finish transmission.\n");
            }

            result.seekg(0, std::ios::beg);
            Callable<void, std::stringstream &&>::call(callback, std::move(result));
        } catch (std::exception &e) {
            //finally simulation, server doesn't need - it catches all the
            // exceptions in its callback
            remove((username + "-response.tcp").c_str());
            throw e;
        }
    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_TRANSMISSION_FILE_CLIENT_H_
