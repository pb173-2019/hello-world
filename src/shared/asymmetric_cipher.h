/**
 * @file asymmetric_cipher.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Asymmetric cipher (e.g. RSA) interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_ASYMMETRICCIPHER_H_
#define HELLOWORLD_SHARED_ASYMMETRICCIPHER_H_

#include <string>
#include <vector>

namespace helloworld {

class AsymmetricKeyGen {
public:
    AsymmetricKeyGen() = default;
    // Copying is not available
    AsymmetricKeyGen(const AsymmetricKeyGen &other) = delete;
    AsymmetricKeyGen &operator=(const AsymmetricKeyGen &other) = delete;
    virtual ~AsymmetricKeyGen() = default;

    /**
     * @brief Save private key into file
     *
     * @param filename file to save the key
     * @param pwd password to encrypt key
     * @return bool true if succesfully saved
     */
    virtual bool savePrivateKey(const std::string& filename, const std::string& pwd) = 0;

    /**
     * @brief Save public key into file
     *
     * @param filename file to save the key
     * @return bool true if succesfully saved
     */
    virtual bool savePublicKey(const std::string& filename) = 0;
};

class AsymmetricCipher {
 friend AsymmetricKeyGen;

 public:
  AsymmetricCipher() = default;
  // Copying is not available
  AsymmetricCipher(const AsymmetricCipher &other) = delete;
  AsymmetricCipher &operator=(const AsymmetricCipher &other) = delete;
  virtual ~AsymmetricCipher() = default;

  /**
   * @brief Set required key for operation
   *
   * @param keyFile key filename to load
   */
  virtual void loadPublicKey(const std::string &keyFile) = 0;

  /**
   * @brief Set required key for operation
   *
   * @param keyFile key filename to load
   * @param pwd password to decrypt private key or empty string
  */
  virtual void loadPrivateKey(const std::string &keyFile, const std::string &pwd) = 0;

  /**
   * @brief Encrypt given message with key given
   *
   * @param msg message to encrypt
   * @return std::vector<unsigned char> encrypted message
   */
  virtual std::vector<unsigned char> encrypt(const std::string &msg) = 0;

  /**
   * @brief Decrypt data with key given
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
  virtual bool verify(const std::vector<unsigned char> &signedData, const std::string &hash) = 0;
};



}  // namespace helloworld

#endif  // HELLOWORLD_SHARED_ASYMMETRICCIPHER_H_
