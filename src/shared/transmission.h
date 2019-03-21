/**
 * @file transmission.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager takes care of all communication
 *  - establishing connection: will recognize request for new chanel and reacts according to it
 *      e.g. X3DH on client-client, challenge on client-server communication
 *  - maintain connection: client / server sets initial session keys, and the transmission manager
 *      takes care of key rotation (double ratchet)
 *  - delete unwanted metadata: will periodically clear
 *  - encodes in base64
 *
 * SEVER side implementation
 *  - implementation manager will also determine where to send the request to process
 *  - does not care of incoming registration, just encrypts and forwards
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
    }
};

template <typename incoming, typename outcoming>
class TransmissionManager {

public:
    TransmissionManager() = default;
    // Copying is not available
    TransmissionManager(const TransmissionManager &other) = delete;
    TransmissionManager &operator=(const TransmissionManager &other) = delete;
    virtual ~TransmissionManager() = default;

    /**
     * Send request / response depending on side
     * @param out outcoming object to send
     */
    virtual void send(const outcoming& out) = 0;

    /**
     * Receive request / response depending on side
     * in TCP, this method is waiting for any incoming request / reponse
     *
     */
    virtual incoming receive() = 0;
};



#endif //HELLOWORLD_TRANSMISSION_H
