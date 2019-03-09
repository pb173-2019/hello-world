//
// Created by horak_000 on 7. 3. 2019.
//

#ifndef ASYMETRIC_CIPHER_INTERFACE
#define ASYMETRIC_CIPHER_INTERFACE

#include <string>
#include <vector>

class IAsymetricCipher {
 public:
  /**
   * Copying is not available
   */
  IAsymetricCipher(const IAsymetricCipher &other) = delete;
  IAsymetricCipher &operator=(const IAsymetricCipher &other) = delete;
  virtual ~IAsymetricCipher() = default;

  /**
   * Set key for operation specified
   * @param key key to set
   * @param op operation to perform
   */
  virtual void setKey(const std::string &key) = 0;

  /**
   * Encrypt given message with key
   * @param msg message to encrypt
   * @return encrypted message
   */
  virtual std::vector<unsigned char> encrypt(const std::string &msg) = 0;

  /**
   * Decrypt data with key and iv given
   * @param data data to decrypt
   * @return original message
   */
  virtual std::string decrypt(const std::vector<unsigned char> &data) = 0;

  /**
   * Sign given message with
   * @param hash hash imprint of data
   * @return signed hash of data
   */
  virtual std::vector<unsigned char> sign(const std::string &hash) = 0;

  /**
   * Verify the signature
   * @param signedData signature to verify
   * @param hash value to compare
   * @return true if signature verified
   */
  virtual bool verify(const std::vector<unsigned char> &signedData,
                      const std::string &hash) = 0;
};

#endif  // ASYMETRIC_CIPHER_INTERFACE
