//
// Created by horak_000 on 7. 3. 2019.
//

#ifndef SYMETRIC_CIPHER_INTERFACE
#define SYMETRIC_CIPHER_INTERFACE

#include <string>
#include <vector>

// enum class Operation {
//    CIPHER_ENCRYPT, CIPHER_DECRYPT
//};

class ISymetricCipher {
 public:
  /**
   * Copying is not available
   */
  ISymetricCipher(const ISymetricCipher &other) = delete;
  ISymetricCipher &operator=(const ISymetricCipher &other) = delete;
  virtual ~ISymetricCipher() = default;

  /**
   * Set cipher key
   * @param key to encrypt or decrypt data
   */
  virtual void setKey(const std::string &key) = 0;

  /**
   * Retrieve the key cipher is working with
   * @return key associated with cipher instance
   */
  virtual std::string getKey() = 0;

  /**
   * Set custom iv for cipher, generated random if not present
   * @param iv initialization vector to increase randomness
   */
  virtual void setIv(const std::string &iv) = 0;

  /**
   * Retrieve the iv cipher is working with
   * @return iv associated with cipher instance
   */
  virtual std::string getIv() = 0;

  /**
   * Encrypt given message with key given (iv is generated if not present)
   * @param msg message to encrypt
   * @return encrypted message
   */
  virtual std::vector<unsigned char> encrypt(const std::string &msg) = 0;

  /**
   * Decrypt data with key and iv given (throws if iv not present)
   * @param data data to decrypt
   * @return original message
   */
  virtual std::string decrypt(const std::vector<unsigned char> &data) = 0;
};

#endif  // SYMETRIC_CIPHER_INTERFACE
