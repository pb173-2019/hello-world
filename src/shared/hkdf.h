//
// Created by ivan on 30.3.19.
//

#ifndef HELLOWORLD_HKDF_H
#define HELLOWORLD_HKDF_H


#include "hmac_base.h"
#include <memory>

namespace helloworld {
    class hkdf {

        std::unique_ptr<hmac> _hash;
        std::string _salt;
        const std::string _info;

        /**
         * extracts pseudo random key from input keying material and salt
         * (based on RFC5869)
         * @param IKM Input Keying material (hex representation)
         * @param salt
         * @return
         */
        std::string _extract(const std::string &IKM, const std::string &salt) const;

        /**
         * expands pseudo random key into output keying material with length len
         * (based on RFC5869)
         * @param PRK pseudo random key
         * @param info application specific inforamtion
         * @param len output length
         * @return hex representation of keying material
         */
        std::string _expand(const std::string &PRK, const std::string &info, size_t len) const;

    public:

        /**
         * default konstruktor of HKDF (HMAC-based key derivation function)
         * @param hash hmac function satisfying hmac interface
         * @param info application specific information ("Hello world!" predefined, different just for testing)
         */
        explicit hkdf(std::unique_ptr<hmac> &&hash = std::make_unique<hmac_base<> >(),
                      std::string info = "Hello world!");

        /**
         * salt setter
         * @param newSalt new hex representation of salt
         */
        void setSalt(const std::string &newSalt);

        /**
         * generates keying material from input keying material
         * @param IKM input keying material, from which keying material will be generated
         * @param outputLength length of output in bytes
         * @return hex representation of output keying material
         */
        std::string generate(const std::string &IKM, size_t outputLength) const;
    };
} // namespace helloworld

#endif //HELLOWORLD_HKDF_H
