/**
 * @file ConnectionManager.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief
 * @version 0.1
 * @date 22. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CONNECTIONMANAGER_H
#define HELLOWORLD_CONNECTIONMANAGER_H

#include "request.h"
#include "rsa_2048.h"

/**
 * Holds the logic of security forwarding
 * to-be containing: double ratchet
 */
class SecurityManager {

protected:
    bool _established = false;
    std::string _sessionKey;
    std::string _iv;
    std::string _macKey;

public:
    void initializeSecurity(std::string key, std::string iv, std::string macKey) {
        _sessionKey = std::move(key);
        _iv = std::move(iv);
        _macKey = std::move(macKey);
        _established = true;
    }
};

#endif //HELLOWORLD_CONNECTIONMANAGER_H
