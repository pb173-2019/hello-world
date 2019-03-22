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
#include <stdexcept>

#include "utils.h"

namespace helloworld {

class TransmissionManager {
protected:
    /**
     * Function that can handle receive() output
     */
    Callable<void, unsigned long, std::stringstream&&>* callback;

public:
    explicit TransmissionManager(Callable<void, unsigned long, std::stringstream&&>* callback) : callback(callback) {
        if (callback == nullptr)
            throw std::runtime_error("Null not allowed.");
    };
    // Copying is not available
    TransmissionManager(const TransmissionManager &other) = delete;
    TransmissionManager &operator=(const TransmissionManager &other) = delete;
    virtual ~TransmissionManager() = default;

    /**
     * @brief Send data
     *
     * @param id connection id
     * @param data data as iostream to process
     */
    virtual void send(unsigned long id, std::iostream& data) = 0;

    /**
     * @brief Receive request / response depending on side
     *        in TCP, this method is waiting for any incoming request / reponse
     *        uses callback to forward unsigned long, std::stringstream
     */
    virtual void receive() = 0;
};

} //namespace helloworld

#endif //HELLOWORLD_TRANSMISSION_H
