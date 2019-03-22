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

#if defined(WINDOWS)

#include <windows.h>
#include <io.h>
#include <map>


#else

#endif


namespace helloworld {

/**
* TCP version will handle id generating
*/
class FileManager : public TransmissionManager {

    helloworld::Base64 _base64;
    std::map<unsigned long, std::string> _files;

public:
    explicit FileManager(Call callback) : TransmissionManager(callback) {};

    // Copying is not available
    FileManager(const FileManager &other) = delete;

    FileManager &operator=(const FileManager &other) = delete;

    ~FileManager() override = default;

    void send(unsigned long id, std::iostream &data) override {
        data.seekg(0, std::ios::beg);

        std::ofstream send{std::to_string(id) + ".tcp", std::ios::binary | std::ios::out};
        if (!send) {
            throw std::runtime_error("Transmission failed.\n");
        }

        while (data.good()) {
            unsigned char buffer[256];
            size_t read = read_n(data, buffer, 256);
            std::vector<unsigned char> encoded = _base64.encode(std::vector<unsigned char>(buffer, buffer + read));
            write_n(send, encoded.data(), encoded.size());
        }
    }

    void receive() override {
        std::string incoming = getIncoming();
        std::ifstream receive{incoming, std::ios::binary | std::ios::in};
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
        callback(exists(incoming), std::move(result));
        incoming.push_back('\0'); //sichr
        if (remove(incoming.c_str()) != 0) {
            throw std::runtime_error("Could not finish transmission.\n");
        }
    }

    /**
     * Mark some connection as opened
     * @param connection
     */
    void registerConnection(unsigned long connection) {
        if (connection == 0)
            return;
        bool inserted = _files.emplace(connection, std::to_string(connection) + ".tcp").second;
        if (!inserted) {
            throw std::runtime_error("Could not register existing connection.");
        }
    }

    /**
     * Release connection
     * @param connection
     */
    void removeConnection(unsigned long connection) {
        _files.erase(connection);
    }

    /**
     * Check filename for its connection
     * @param filename name to check
     * @return 0 if no connection found, otherwise >0
     */
    unsigned long exists(const std::string& filename) {
        for (auto& item : _files) {
            if (item.second == filename) {
                return item.first;
            }
        }
        return 0;
    }

private:
    //from https://stackoverflow.com/questions/11140483/how-to-get-list-of-files-with-a-specific-extension-in-a-given-folder

    /**
     * Get the
     */
#if defined(WINDOWS)

    std::string getIncoming() {
        std::string file;

        WIN32_FIND_DATAA data;
        HANDLE handle = FindFirstFile(".\\*", &data);

        long hFile;

        if (handle) {
            do {
                std::wcout << data.cFileName << std::endl;
                if (strstr(data.cFileName, ".tcp")) {
                    file = data.cFileName;
                    break;
                }
            } while ( FindNextFile(handle, &data));
            FindClose(handle);
        }
        return file;
    }

#else
    std::string getIncoming() {
       std::string file;
       DIR* dirFile = opendir( "." );
       if ( dirFile ) {
          struct dirent* hFile;
          errno = 0;
          while (( hFile = readdir( dirFile )) != nullptr ) {
             if ( strstr( hFile->d_name, ".tcp" )) {
                  file = hFile->d_name;
                  break;
             }
          }
          closedir( dirFile );
       }
       return file;
    }
#endif
};

} //namespace helloworld

#endif //HELLOWORLD_TRANSMISSION_H
