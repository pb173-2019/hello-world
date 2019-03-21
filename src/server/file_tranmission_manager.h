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

#include "../shared/request.h"
#include "../shared/transmission.h"

/**
 * Incoming: std::string (filename)
 * Outcomming: Response (from user)
 */
class FileTransmissionManager : public TransmissionManager<> {

    std::map<int, SecurityManager> _securities;

public:



};


#endif //HELLOWORLD_FILE_TRANMISSION_MANAGER_H
