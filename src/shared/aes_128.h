/**
 * @file aes_128.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief AES128 wrapper
 * @version 0.1
 * @date 2019-03-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_AES_128_H_
#define HELLOWORLD_SHARED_AES_128_H_

#include <iostream>
#include <vector>

#include "symmetric_cipher_base.h"
#include "random.h"
#include "utils.h"
#include "serializable_error.h"

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace helloworld {

//for testing purposes


    class AES128 : public SymmetricCipherBase<MBEDTLS_CIPHER_AES_128_CBC> {

public:

        explicit AES128() = default;

    AES128(const AES128& other) = delete;
    AES128&operator=(const AES128& other) = delete;

        ~AES128() = default;

    void encrypt(std::istream &in, std::ostream &out) override;

    void decrypt(std::istream &in, std::ostream &out) override;

};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_AES_128_H_
