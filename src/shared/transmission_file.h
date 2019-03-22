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

#ifndef HELLOWORLD_SHARED_TRANSMISSION_FILE_H_
#define HELLOWORLD_SHARED_TRANSMISSION_FILE_H_

#include <string>
#include <tuple>
#include <iostream>
#include <fstream>
#include <sstream>

#include "transmission.h"
#include "base_64.h"
#include "utils.h"

namespace helloworld {

/**
* TCP version will handle id generating
*/
class FileManager : public TransmissionManager {

    helloworld::Base64 base64;

public:
    explicit FileManager(Call callback) : TransmissionManager(callback) {};
    // Copying is not available
    FileManager(const FileManager &other) = delete;
    FileManager &operator=(const FileManager &other) = delete;
    ~FileManager() = default;

    void send(unsigned long id, std::iostream& data) override {
        data.seekg(0, std::ios::beg);

        std::ofstream send{std::to_string(id) + ".tcp", std::ios::binary | std::ios::out};
        if (!send) {
            throw std::runtime_error("Transmission failed.\n");
        }

        while (data.good()) {
            unsigned char buffer[256];
            size_t read = read_n(data, buffer, 256);
            std::vector<unsigned char> encoded = base64.encode(std::vector<unsigned char>(buffer, buffer + read));
            write_n(send, encoded.data(), encoded.size());
        }
    }

    void receive() override {
        std::cout << "Not implemented in file manager, use the other with filename.\n";
        throw std::runtime_error("Not implemented.\n");
    }

    /**
     * Receive request / response depending on side
     * this version simulates the TCP ability to recognize new connection
     *
     * @param cid identifier of the connection / testing purposes
     */
    void receive(unsigned long cid) {
        std::ifstream receive{std::to_string(cid) + ".tcp", std::ios::binary | std::ios::in};
        if (!receive) {
            throw std::runtime_error("Transmission failed.\n");
        }

        std::stringstream result{};
        while (receive.good()) {
            unsigned char buffer[256];
            size_t read = read_n(receive, buffer, 256);
            std::vector<unsigned char> decoded = base64.decode(std::vector<unsigned char>(buffer, buffer + read));
            write_n(result, decoded.data(), decoded.size());
        }
        result.seekg(0, std::ios::beg);
        callback(cid, std::move(result));
    }
};

} //namespace helloworld

#endif //HELLOWORLD_TRANSMISSION_H
