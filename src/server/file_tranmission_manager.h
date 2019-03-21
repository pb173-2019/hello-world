/**
 * @file file_tranmission_manager.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief
 * @version 0.1
 * @date 21. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_FILE_TRANMISSION_MANAGER_H_
#define HELLOWORLD_SERVER_FILE_TRANMISSION_MANAGER_H_

#include <map>

#include "../shared/request.h"
#include "../shared/transmission.h"

/**
 * Incoming: Request (from user)
 * Outcomming: Response
 */
class FileTransmissionManager : public TransmissionManager<helloworld::Request, helloworld::Response> {

    std::map<int, SecurityManager> _securities;

public:
    FileTransmissionManager() = default;
    // Copying is not available
    FileTransmissionManager(const FileTransmissionManager &other) = delete;
    FileTransmissionManager &operator=(const FileTransmissionManager &other) = delete;
    ~FileTransmissionManager() override = default;

    void send(const helloworld::Response& out) override;

    helloworld::Request receive() override;

};


#endif //HELLOWORLD_FILE_TRANMISSION_MANAGER_H
