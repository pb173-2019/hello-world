/**
 * @file Client.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Client interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HW_CLIENT_INCLUDE_CLIENT_H_
#define HW_CLIENT_INCLUDE_CLIENT_H_

#include <string>
#include <vector>

#include "Connection.h"
#include "SecureChannel.h"

namespace helloworld {

struct UserData {
  long id;
  std::string name;
};

class Client {
  // specific connection
  Connection connection;

 public:
  /**
   * @brief Connect user to the server with given info
   *
   * @param username name of user
   * @param password password of user
   */
  void login(const std::string& username, const std::string& password);

  /**
   * @brief Log out the user from server
   *
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
   *
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

#endif  // HW_CLIENT_INCLUDE_CLIENT_H_
