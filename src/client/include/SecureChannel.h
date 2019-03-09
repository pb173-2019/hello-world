//
// Created by horak_000 on 8. 3. 2019.
//

#ifndef HELLO_WORLD_SECURECHANNEL_H
#define HELLO_WORLD_SECURECHANNEL_H

class SecureChannel {

public:

    /**
     * Create secure channel
     * @param id user id
     */
    SecureChannel(long id);

    /**
     * Send data package
     * @msg message to send
     */
    void send(const std::string& msg);

    /**
     * Request message from user
     * @msg message to send
     * @msgId message id to receive
     */
    std::string receive(long msgId);
};

#endif //HELLO_WORLD_SECURECHANNEL_H
