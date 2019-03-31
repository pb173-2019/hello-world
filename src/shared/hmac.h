/**
 * @file hmac.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief HMAC class (SHA-512)
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_HMAC_H
#define HELLOWORLD_HMAC_H

namespace helloworld {

    class hmac {
    public:
        virtual size_t hmacLength() const = 0;

        virtual void setKey(const std::string &newKey) = 0;

        virtual std::vector<unsigned char> generate(const std::vector<unsigned char> &message) const = 0;

        virtual ~hmac() = default;
    };



} // helloworld

#endif //HELLOWORLD_HMAC_H
