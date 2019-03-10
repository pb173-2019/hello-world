/**
 * @file encode.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Base64 encoder interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_ENCODE_H_
#define HELLOWORLD_SHARED_ENCODE_H_

#include <string>
#include <vector>

namespace helloworld {

template <typename raw, typename encoded>
class Encode {
 public:
  Encode(const Encode& other) = delete;
  Encode& operator=(const Encode& other) = delete;
  virtual ~Encode() = default;

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

// Alias for default type encoder to get rid of templates
using Base64Encoder = Encode<std::string, std::vector<unsigned char>>;

}  // namespace helloworld

#endif  // HELLOWORLD_SHARED_ENCODE_H_
