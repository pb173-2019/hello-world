/**
 * @file ISymmetricCipher.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Symmetric cipher (e.g. AES) interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef HW_CLIENT_INCLUDE_ISYMMETRICCIPHER_H_
#define HW_CLIENT_INCLUDE_ISYMMETRICCIPHER_H_

#include <string>
#include <vector>

namespace helloworld {

class ISymmetricCipher {
 public:
  // Copying is not available
  ISymmetricCipher(const ISymmetricCipher &other) = delete;
  ISymmetricCipher &operator=(const ISymmetricCipher &other) = delete;
  virtual ~ISymmetricCipher() = default;

  /**
   * @brief Set cipher key
   *
   * @param key key to encrypt or decrypt data
   */
  virtual void setKey(const std::string &key) = 0;

  /**
   * @brief Retrieve the key the cipher is working with
   *
   * @return std::string key associated with cipher instance
   */
  virtual std::string getKey() = 0;

  /**
   * @brief Set custom iv for cipher, generated random if not present
   *
   * @param iv initialization vector to increase randomness
   */
  virtual void setIv(const std::string &iv) = 0;

  /**
   * @brief Retrieve the iv cipher is working with
   *
   * @return std::string iv associated with cipher instance
   */
  virtual std::string getIv() = 0;

  /**
   * @brief Encrypt given message with key given (iv is generated if not
   * present)
   *
   * @param msg message to encrypt
   * @return std::vector<unsigned char> encrypted message
   */
  virtual std::vector<unsigned char> encrypt(const std::string &msg) = 0;

  /**
   * @brief Decrypt data with key and iv given (throws if iv not present)
   *
   * @param data data to decrypt
   * @return std::string original message
   */
  virtual std::string decrypt(const std::vector<unsigned char> &data) = 0;
};

}  // namespace helloworld

#endif  // HW_CLIENT_INCLUDE_ISYMMETRICCIPHER_H_
