/**
 * @file server.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Server interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_SERVER_H_
#define HELLOWORLD_SERVER_SERVER_H_

#include <string>

#include "shared/request_type.h"

namespace helloworld {

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
   * @brief Handle incoming request on user port
   *
   * @param request request from user
   * @return Response response data
   */
  Response handleUserRequest(const Request &request);

  /**
   * @brief Handle incoming request for system on system port
   *
   * @return long connection id
   */
  long establishConnection();

  /**
   * @brief Terminate connection
   *
   * @param cid connection id
   */
  void terminateConnection(long cid);
};

}  // namespace helloworld

#endif  // HELLOWORLD_SERVER_SERVER_H_