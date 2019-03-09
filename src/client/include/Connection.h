/**
 * @file Connection.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Connection interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HW_CLIENT_INCLUDE_CONNECTION_H_
#define HW_CLIENT_INCLUDE_CONNECTION_H_

namespace helloworld {

enum class RequestType { LOGIN, LOGOUT, CREATE, DELETE, SEND, RECEIVE, FIND };

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
   * @brief Connect user to the server with given info
   *
   * @param address address of the server
   */
  Connection(const std::string& address);

  // Disconnects from server
  ~Connection();

  /**
   * @brief Request generic operation of server
   *
   * @param request request
   * @return Response response object
   */
  Response sendRequest(Request request);

  /**
   * @brief Establish secure channel with other user. Will use X3DH protocol.
   *
   * @param id  id of user to establish the secure channel with
   * @return SecureChannel secure channel instance
   */
  SecureChannel openSecureChannel(long id);

  /**
   * @brief Close secure channel with user
   *
   * @param id user id
   */
  void closeSecureChannel(long id);

  /**
   * @brief Send message to the user
   *
   * @param message message body
   * @param id user id to send message to
   */
  void sendMessage(const std::string& message, long id);
};

}  // namespace helloworld

#endif  // HELLO_WORLD_CONNECTION_H
