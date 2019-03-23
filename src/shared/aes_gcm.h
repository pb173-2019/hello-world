//
// Created by ivan on 23.3.19.
//

#ifndef HELLOWORLD_AES_GCM_H
#define HELLOWORLD_AES_GCM_H
#include "config.h"
#include "symmetric_cipher_base.h"
#include "mbedtls/cipher.h"
#include <sstream>
#include <array>

namespace helloworld {

    class AESGCM : public SymmetricCipherBase<MBEDTLS_CIPHER_AES_128_GCM, 16, 12>
            {
        void _additional(std::istream& ad);
    public:
        AESGCM() = default;

        AESGCM(const AESGCM& other) = delete;
        AESGCM&operator=(const AESGCM& other) = delete;
        ~AESGCM() = default;

        void encrypt(std::istream &in, std::ostream &out) override;

        void encryptWithAd(std::istream &in, std::istream& ad, std::ostream &out);

        void decrypt(std::istream &in, std::ostream &out) override;

        void decryptWithAd(std::istream &in, std::istream& ad,std::ostream &out) ;


    };


} //namespace helloworld


#endif //HELLOWORLD_AES_GCM_H
