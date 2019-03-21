/**
 * @file base_64.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Base64 wrapper, implements encode inteface
 * @version 0.1
 * @date 13. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "encode.h"

#ifndef HELLOWORLD_SHARED_BASE64_H_
#define HELLOWORLD_SHARED_BASE64_H_

namespace helloworld {

using Encoder = Encode<std::vector<unsigned char>, std::vector<unsigned char>>;

class Base64 : public Encoder {

public:
    Base64() = default;
    Base64(const Base64& other) = delete;
    Base64& operator=(const Base64& other) = delete;
    ~Base64() override = default;

    std::vector<unsigned char> encode(const std::vector<unsigned char>& message) override;

    std::vector<unsigned char> decode(const std::vector<unsigned char>& data) override;
};

} // namespace helloworld

#endif //HELLOWORLD_SHARED_BASE64_H_
