/**
 * @file encode.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Encode interface
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
  Encode() = default;
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

  /**
   * @brief Encode input stream into base64 & write to output stream
   *        base64 has delimiters -> encode 256 blocks by lines
   *
   * @param toEncode stream to encode
   * @param out encoded stream
   */
  virtual void fromStream(std::istream &toEncode, std::ostream &out) = 0;

    /**
     * @brief Decode input stream into original form
     *        base64 has delimiters -> get file by lines and encode as single blocks
     *
     * @param toDecode stream to decode
     * @param out original stream
     */
  virtual void toStream(std::istream &toDecode, std::ostream &out) = 0;
};

}  // namespace helloworld

#endif  // HELLOWORLD_SHARED_ENCODE_H_
