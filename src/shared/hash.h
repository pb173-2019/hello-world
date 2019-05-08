/**
 * @file hash.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Hash function (e.g. MD5, SHA) interface
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_HASH_H_
#define HELLOWORLD_SHARED_HASH_H_

#include <string>
#include <vector>

#include "key.h"

namespace helloworld {

class Hash {
   public:
    Hash() = default;

    // Copying is not available
    Hash(const Hash &other) = delete;

    Hash &operator=(const Hash &other) = delete;

    virtual ~Hash() = default;

    /**
     * @brief Hash given data in stream
     *
     * @param in data to hash
     * @return std::string hashed input in HEX string form
     */
    virtual std::string getHex(std::istream &in) = 0;

    /**
     * @brief Hash given data in string
     *
     * @param in data to hash
     * @return std::string hashed input in HEX string form
     */
    virtual std::string getHex(const std::string &in) = 0;
    virtual std::string getHex(const zero::str_t &in) = 0;

    /**
     * @brief Get safe data
     *
     * @param in input from which to generate
     * @return zero::str_t data which will be erased from memory on dealloc
     */
    virtual zero::str_t getSafeHex(const zero::str_t &in) = 0;

    /**
     * @brief Hash given data in stream
     *
     * @param in data to hash
     * @return std::vector<unsigned char> hashed input in bytes
     */
    virtual std::vector<unsigned char> get(std::istream &in) = 0;

    /**
     * @brief Hash given data in string
     *
     * @param in data to hash
     * @return std::vector<unsigned char> hashed input in bytes
     */
    virtual std::vector<unsigned char> get(const std::string &in) = 0;

    /**
     * @brief Get safe hash
     *
     * @param in data to hash
     * @return zero::bytes_t data which will be erased from memory on dealloc
     */
    virtual zero::bytes_t getSafe(const std::string &in) = 0;
    virtual zero::bytes_t getSafe(const zero::str_t &in) = 0;
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_HASH_H_
