//
// Created by horak_000 on 8. 3. 2019.
//

#ifndef HELLO_WORLD_CONNECTION_H
#define HELLO_WORLD_CONNECTION_H


enum class RequestType {
    LOGIN, LOGOUT, CREATE, DELETE, SEND, RECEIVE, FIND
};

struct Request {
    RequestType type;
};

struct Response {
    bool successful;
    size_t size;

};

class Connection {

public:
    /**
     * Connect user to the server with given info
     * @param address address of the server
     */
    Connection(const std::string& address);

    /**
     * Disconnects from server
     */
    ~Connection();

    /**
     * Request generic operation of server
     * @param request request message
     * @return server Response object
     */
    Response sendRequest(Request request);

    /**
     * Establish secure channel with other user. Will use X3DH protocol.
     * @param id id of user to establish the secure channel with
     * @return secure channel instance
     */
    SecureChannel openSecureChannel(long id);

    /**
     * Close secure channel with user
     * @param id user id
     */
    void closeSecureChannel(long id);

    /**
     * Send message to the user
     * @param msg message body
     * @param id user id to send message to
     */
    void sendMessage(const std::string& msg, long id);
};


#endif //HELLO_WORLD_CONNECTION_H
