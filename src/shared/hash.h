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
     * @return std::string hashed input
     */
    virtual std::string get(std::istream &in) = 0;
};

}  // namespace helloworld

#endif  // HELLOWORLD_SHARED_HASH_H_
