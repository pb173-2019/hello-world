/**
 * @file hkdf.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief hmac based key derivation function (class)
 * @version 0.1
 * @date 2019-03-30
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_HKDF_H
#define HELLOWORLD_HKDF_H

#include "hmac_base.h"
#include <memory>

namespace helloworld {

class hkdf {

    std::unique_ptr<hmac> _hash;
    zero::str_t _salt;
    const zero::str_t _info;

    /**
     * extracts pseudo random key from input keying material and salt
     * (based on RFC5869)
     * @param IKM Input Keying material (hex representation)
     * @param salt
     * @return
     */
    zero::str_t _extract(const zero::str_t &IKM, const zero::str_t &salt) const;

    /**
     * expands pseudo random key into output keying material with length len
     * (based on RFC5869)
     * @param PRK pseudo random key
     * @param info application specific inforamtion
     * @param len output length
     * @return hex representation of keying material
     */
    zero::str_t _expand(const zero::str_t &PRK, const zero::str_t &info, size_t len) const;

public:

    /**
     * default konstruktor of HKDF (HMAC-based key derivation function)
     * @param hash hmac function satisfying hmac interface
     * @param info application specific information ("Hello world!" predefined, different just for testing)
     */
    explicit hkdf(std::unique_ptr<hmac> &&hash = std::make_unique<hmac_base<> >(),
                  zero::str_t info = "Hello world!");

    /**
     * salt setter
     * @param newSalt new hex representation of salt
     */
    void setSalt(const zero::str_t &newSalt);

    /**
     * generates keying material from input keying material
     * @param IKM input keying material, from which keying material will be generated
     * @param outputLength length of output in bytes
     * @return hex representation of output keying material
     */
    zero::str_t generate(const zero::str_t &IKM, size_t outputLength) const;
};

} // namespace helloworld

#endif //HELLOWORLD_HKDF_H
