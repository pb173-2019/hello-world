//
// Created by horak_000 on 7. 3. 2019.
//

#ifndef ENCODER_INTERFACE
#define ENCODER_INTERFACE

#include <string>
#include <vector>

template <typename raw, typename encoded>
class IEncode {
 public:
  IEncode(const IEncode& other) = delete;
  IEncode& operator=(const IEncode& other) = delete;
  virtual ~IEncode() = default;

  /**
   * Encode the given data to prevent system ambiguity
   * @param message message to encode
   * @return encoded data
   */
  virtual encoded encode(const raw& message) = 0;

  /**
   * Decode the given data to human - readable form
   * @param data data to decode
   * @return decoded message
   */
  virtual raw decode(const encoded& data) = 0;
};

/**
 * Alias for default - type - encoder, to get rid of templates
 */
using Base64Encoder = IEncode<std::string, std::vector<unsigned char>>;

#endif  // ENCODER_INTERFACE
