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

#include "key.h"

namespace helloworld {

enum class KeyType { PUBLIC_KEY, PRIVATE_KEY, NO_KEY };

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
     * @param key key for aes
     * @param iv iv for aes
     * @return bool true if succesfully saved
     */
    virtual bool savePrivateKey(const std::string &filename,
                                const zero::str_t &key,
                                const std::string &iv) = 0;

    /**
     * @brief Save private key into file
     *
     * @param filename file to save the key
     * @param pwd password to protect the key
     * @return bool true if succesfully saved
     */
    virtual bool savePrivateKeyPassword(const std::string &filename,
                                        const zero::str_t &pwd) = 0;

    /**
     * @brief Save public key into file
     *
     * @param filename file to save the key
     * @return bool true if succesfully saved
     */
    virtual bool savePublicKey(const std::string &filename) const = 0;

    /**
     * Direct getter for public key
     *
     * @return zero::bytes_t public key
     */
    virtual zero::bytes_t getPublicKey() const = 0;
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
     * Direct setter for public key
     *
     * @param key public key in pem format
     */
    virtual void setPublicKey(const zero::bytes_t &key) = 0;

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
     * @param key key to decrypt private key or empty string
     * @param iv iv for encryption or empty string if not encrypted
     */
    virtual void loadPrivateKey(const std::string &keyFile,
                                const zero::str_t &key,
                                const std::string &iv) = 0;

    /**
     * @brief Set required key for operation
     *
     * @param keyFile key filename to load
     * @param pwd password to decrypt key
     */
    virtual void loadPrivateKey(const std::string &keyFile,
                                const zero::str_t &pwd) = 0;

    /**
     * @brief Encrypt given message with key given
     *
     * @param data data to encrypt
     * @return std::vector<unsigned char> encrypted message
     */
    virtual std::vector<unsigned char> encrypt(
        const std::vector<unsigned char> &data) = 0;

    /**
     * @brief Decrypt data with key given
     *
     * @param data data data to decrypt
     * @return std::string original message
     */
    virtual std::vector<unsigned char> decrypt(
        const std::vector<unsigned char> &data) = 0;

    /**
     * @brief Sign given message with hash imprint of data
     *
     * @param hash hash to sign (either HEX string or raw buffer)
     * @return std::vector<unsigned char> signed hash of data
     */
    virtual std::vector<unsigned char> sign(
        const std::vector<unsigned char> &data) = 0;
    virtual std::vector<unsigned char> sign(const std::string &data) = 0;

    /**
     * @brief Verify the signature
     *
     * @param signedData signature to verify
     * @param hash hash to sign (either HEX string or raw buffer)
     * @return true if signature was verified correctly
     * @return false if signature was not verified correctly
     */
    virtual bool verify(const std::vector<unsigned char> &signedData,
                        const std::vector<unsigned char> &data) = 0;
    virtual bool verify(const std::vector<unsigned char> &signedData,
                        const std::string &data) = 0;
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_ASYMMETRICCIPHER_H_
