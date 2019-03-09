//
// Created by horak_000 on 8. 3. 2019.
//

#ifndef HELLO_WORLD_SERVER_H
#define HELLO_WORLD_SERVER_H

struct Request {
    RequestType type;
};

struct Response {
    bool successful;
    size_t size;

};


class Server {

public:

    /**
     * Handle incoming request on user port
     * @param request from user
     * @return response data
     */
    Response handleUserRequest(const Request &request);

    /**
     * Handle incoming request for system on system port
     * @return connection id
     */
    long establishConnection();

    /**
     * Terminate connection
     * @param cid connection id
     */
    void terminateConnection(long cid);
};


#endif //HELLO_WORLD_SERVER_H
