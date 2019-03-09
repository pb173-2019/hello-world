/**
 * @file IEncode.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Base64 encoder interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef HW_CLIENT_INCLUDE_IENCODE_H_
#define HW_CLIENT_INCLUDE_IENCODE_H_

#include <string>
#include <vector>

namespace helloworld {

// Alias for default - type - encoder, to get rid of templates
using Base64Encoder = IEncode<std::string, std::vector<unsigned char>>;

template <typename raw, typename encoded>
class IEncode {
 public:
  IEncode(const IEncode& other) = delete;
  IEncode& operator=(const IEncode& other) = delete;
  virtual ~IEncode() = default;

  /**
   * @brief Encode the given data to prevent system ambiguity
   *
   * @param message message to encode
   * @return encoded encoded data
   */
  virtual encoded encode(const raw& message) = 0;

  /**
   * @brief Decode the given data to human-readable form
   *
   * @param data data to decode
   * @return raw decoded message
   */
  virtual raw decode(const encoded& data) = 0;
};

}  // namespace helloworld

#endif  // HW_CLIENT_INCLUDE_IENCODE_H_
