/**
 * @file transmission.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager takes care of stream tranmission
 *  - notifies server about new connection request
 *  - generates ids for connection
 *  - uses encoder
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

#include "utils.h"
#include "serializable_error.h"

namespace helloworld {

class TransmissionManager {
protected:
    /**
     * Function that can handle receive() output
     */
    Callable<void, const std::string&, std::stringstream&&>* callback;

public:
    explicit TransmissionManager(Callable<void, const std::string&, std::stringstream&&>* callback) : callback(callback) {
        if (callback == nullptr)
            throw Error("Null not allowed.");
    };
    // Copying is not available
    TransmissionManager(const TransmissionManager &other) = delete;
    TransmissionManager &operator=(const TransmissionManager &other) = delete;
    virtual ~TransmissionManager() = default;

    /**
     * @brief Send data
     *
     * @param usrname user name as connection id
     * @param data data as iostream to process
     */
    virtual void send(const std::string& usrname, std::iostream& data) = 0;

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
    virtual void registerConnection(const std::string& usrname) = 0;

    /**
     * Release connection
     * @param connection
     */
    virtual void removeConnection(const std::string& usrname) = 0;
};

} //namespace helloworld

#endif //HELLOWORLD_TRANSMISSION_H
