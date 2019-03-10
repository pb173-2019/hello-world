/**
 * @file secure_channel.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Secure channel interface
 * @version 0.1
 * @date 2019-03-08
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_SECURECHANNEL_H_
#define HELLOWORLD_CLIENT_SECURECHANNEL_H_

#include <string>

namespace helloworld {

class SecureChannel {
 public:
  /**
   * @brief Create secure channel
   *
   * @param id user id
   */
  explicit SecureChannel(long id);

  /**
   * @brief Send data package
   *
   * @param message message to send
   */
  void send(const std::string& message);

  /**
   * @brief Request message from user
   *
   * @param messageId message id to receive
   * @return std::string message text
   */
  std::string receive(long messageId);
};

}  // namespace helloworld

#endif  // HELLOWORLD_CLIENT_SECURECHANNEL_H_
