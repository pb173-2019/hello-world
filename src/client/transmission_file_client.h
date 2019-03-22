/**
 * @file transmission_file.h
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

#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"

namespace helloworld {

/**
* TCP version will handle id generating
*/
class FileManager : public UserTransmissionManager {

    helloworld::Base64 _base64;

public:
    explicit FileManager(Callable<void, std::stringstream &&> *callback,
                         std::string username) : UserTransmissionManager(callback, std::move(username)) {};

    // Copying is not available
    FileManager(const FileManager &other) = delete;

    FileManager &operator=(const FileManager &other) = delete;

    ~FileManager() override = default;

    void send(std::iostream &data) override {
        data.seekg(0, std::ios::beg);

        std::ofstream send{username + ".tcp", std::ios::binary | std::ios::out};
        if (!send) {
            throw Error("Transmission failed.\n");
        }

        while (data.good()) {
            unsigned char buffer[256];
            size_t read = read_n(data, buffer, 256);
            std::vector<unsigned char> encoded = _base64.encode(std::vector<unsigned char>(buffer, buffer + read));
            write_n(send, encoded.data(), encoded.size());
        }
    }

    void receive() override {
        std::ifstream receive{username + ".tcp", std::ios::binary | std::ios::in};
        if (!receive) {
            return;
        }

        std::stringstream result{};
        while (receive.good()) {
            unsigned char buffer[256];
            size_t read = read_n(receive, buffer, 256);
            std::vector<unsigned char> decoded = _base64.decode(std::vector<unsigned char>(buffer, buffer + read));
            write_n(result, decoded.data(), decoded.size());
        }

        result.seekg(0, std::ios::beg);
        Callable<void, std::stringstream &&>::call(callback, std::move(result));
        if (remove((username + ".tcp").c_str()) != 0) {
            throw Error("Could not finish transmission.\n");
        }
    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_TRANSMISSION_FILE_CLIENT_H_
