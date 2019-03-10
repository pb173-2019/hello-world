/**
 * @file connection.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Connection interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_CONNECTION_H_
#define HELLOWORLD_CLIENT_CONNECTION_H_

#include <string>

#include "secure_channel.h"
#include "shared/request_type.h"

namespace helloworld {

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
   * @brief Connect user to server with given info.
   *
   * @param address address of the server
   */
  explicit Connection(const std::string& address);

  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = default;

  /**
   * @brief Disconnect user from server.
   *
   */
  ~Connection();

  /**
   * @brief Request generic operation of server.
   *
   * @param request request
   * @return Response response object
   */
  Response sendRequest(Request request);

  /**
   * @brief Establish secure channel with other user. Will use X3DH protocol.
   *
   * @param id id of user to establish the secure channel with
   * @return SecureChannel secure channel instance
   */
  SecureChannel openSecureChannel(long id);

  /**
   * @brief Close secure channel with user.
   *
   * @param id user id
   */
  void closeSecureChannel(long id);

  /**
   * @brief Send message to the user.
   *
   * @param message message body
   * @param id user id to send message to
   */
  void sendMessage(const std::string& message, long id);
};

}  // namespace helloworld

#endif  // HELLOWORLD_CLIENT_CONNECTION_H_
