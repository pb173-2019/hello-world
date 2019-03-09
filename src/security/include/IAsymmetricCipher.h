/**
 * @file IAsymmetricCipher.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Asymmetric cipher (e.g. RSA) interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HW_SECURITY_INCLUDE_IASYMMETRICCIPHER_H_
#define HW_SECURITY_INCLUDE_IASYMMETRICCIPHER_H_

#include <string>
#include <vector>

namespace helloworld {

class IAsymmetricCipher {
 public:
  // Copying is not available
  IAsymmetricCipher(const IAsymmetricCipher &other) = delete;
  IAsymmetricCipher &operator=(const IAsymmetricCipher &other) = delete;
  virtual ~IAsymmetricCipher() = default;

  /**
   * @brief Set key for operation specified
   *
   * @param key key to set
   */
  virtual void setKey(const std::string &key) = 0;

  /**
   * @brief Encrypt given message with key
   *
   * @param msg message to encrypt
   * @return std::vector<unsigned char> encrypted message
   */
  virtual std::vector<unsigned char> encrypt(const std::string &msg) = 0;

  /**
   * @brief Decrypt data with key and iv given
   *
   * @param data data data to decrypt
   * @return std::string original message
   */
  virtual std::string decrypt(const std::vector<unsigned char> &data) = 0;

  /**
   * @brief Sign given message with hash imprint of data
   *
   * @param hash
   * @return std::vector<unsigned char> signed hash of data
   */
  virtual std::vector<unsigned char> sign(const std::string &hash) = 0;

  /**
   * @brief Verify the signature
   *
   * @param signedData signature to verify
   * @param hash value to compare
   * @return true if signature was verified correctly
   * @return false if signature was not verified correctly
   */
  virtual bool verify(const std::vector<unsigned char> &signedData,
                      const std::string &hash) = 0;
};

}  // namespace helloworld

#endif  // HW_SECURITY_INCLUDE_IASYMMETRICCIPHER_H_