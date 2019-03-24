
/**
 * @file symmetric_cipher.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Symmetric cipher (e.g. AES) interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_SYMMETRICCIPHER_H_
#define HELLOWORLD_SHARED_SYMMETRICCIPHER_H_

#include <string>
#include <vector>

namespace helloworld {

enum class Padding;

class SymmetricCipher {
public:
    SymmetricCipher() = default;

    // Copying is not available
    SymmetricCipher(const SymmetricCipher &other) = delete;

    SymmetricCipher &operator=(const SymmetricCipher &other) = delete;

    virtual ~SymmetricCipher() = default;

    /**
     * @brief Set cipher key
     *
     * @param key key to encrypt or decrypt data
     * @return bool true if key succesfully set
     */
    virtual bool setKey(const std::string &key) = 0;

    /**
     * @brief Retrieve the key the cipher is working with
     *
     * @return std::string key associated with cipher instance
     */
    virtual const std::string &getKey() const = 0;

    /**
     * @brief Set custom iv for cipher, generated random if not present
     *
     * @param iv initialization vector to increase randomness
     * @return bool true if iv set succesfully
     */
    virtual bool setIv(const std::string &iv) = 0;

    /**
     * @brief Retrieve the iv cipher is working with
     *
     * @return std::string iv associated with cipher instance
     */
    virtual const std::string &getIv() const = 0;

    /**
     * @brief Set cipher padding, fot test purposes
     *
     * @param p padding to set
     */
    virtual void setPadding(Padding p) = 0;

    /**
     * @brief Encrypt given message with key given (iv is generated if not
     * present)
     *
     * @param in data to encrypt
     * @param out enrypted data
     */
    virtual void encrypt(std::istream &in, std::ostream &out) = 0;

    /**
     * @brief Decrypt data with key and iv given (throws if iv not present)
     *
     * @param in data to decrypt
     * @param out decrypted data
     */
    virtual void decrypt(std::istream &in, std::ostream &out) = 0;

    /**
     * Key generator
     *
     * @return std::string key in hex string suitable for cipher
     */
    virtual std::string generateKey() const = 0;
};

}  // namespace helloworld
#endif // HELLOWORLD_SHARED_SYMMETRICCIPHER_H_
