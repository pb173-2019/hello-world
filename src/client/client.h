/**
 * @file client.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Client interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_CLIENT_H_
#define HELLOWORLD_CLIENT_CLIENT_H_

#include <string>
#include <vector>

#include "connection.h"
#include "secure_channel.h"

namespace helloworld {

class Client {
  // specific connection
  Connection _connection;

 public:
  /**
   * @brief Connect user to the server with given info.
   *
   * @param username name of user
   * @param password password of user
   */
  void login(const std::string& username, const std::string& password);

  /**
   * @brief Log out the user from server.
   */
  void logout();

  /**
   * @brief Send request to the server to register new user
   *
   * @param username  name of user
   * @param password password of user
   */
  void createAccount(const std::string& username, const std::string& password);

  /**
   * @brief Permanently deletes the user from server
   */
  void deleteAccount();

  /**
   * @brief Get user list based on given query
   *
   * @param query query to perform search
   * @return std::vector<UserData> list of users matching the given query
   */
  std::vector<UserData> getUsers(const std::string& query);
};

}  // namespace helloworld

#endif  // HELLOWORLD_CLIENT_CLIENT_H_
