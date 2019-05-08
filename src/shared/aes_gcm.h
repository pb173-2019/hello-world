/**
 * @file aes_gcm.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief request and response structures
 * @version 0.1
 * @date 2019-03-24
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef HELLOWORLD_AES_GCM_H
#define HELLOWORLD_AES_GCM_H

#include "config.h"
#include "symmetric_cipher_base.h"
#include "mbedtls/cipher.h"
#include <sstream>
#include <array>

namespace helloworld {

class AESGCM : public SymmetricCipherBase<MBEDTLS_CIPHER_AES_128_GCM, 16, 12> {
    static constexpr size_t TAG_LEN = 16;
    /**
     * @brief Processes additional data
     *
     * @param ad additional data stream to process
     */
    void _additional(std::istream &ad);

    /**
     * @brief Processes additional data
     *
     * @param ad additional data vector to process
     */
    void _additional(const std::vector<unsigned char> &ad);

public:
    AESGCM() {
        setPadding(Padding::PKCS7);
    };

    AESGCM(const AESGCM &other) = delete;

    AESGCM &operator=(const AESGCM &other) = delete;

    ~AESGCM() override = default;

    /**
     * @brief Encrypts and authenticates data in input stream
     *        and writes authentication tag with encrypted data to output
     *
     * @param in input stream
     * @param out output stream
     */
    void encrypt(std::istream &in, std::ostream &out) override;

    /**
     * @brief Encrypts and authenticates with additional data (additional data are not written into output)
     *
     * @param in input stream
     * @param ad additional data stream
     * @param out output stream
     */
    void encryptWithAd(std::istream &in, std::istream &ad, std::ostream &out);

    /**
     * @brief Encrypts and authenticates with additional data (additional data are not written into output)
     *
     * @param in input vector
     * @param ad additional data vector
     * @param out output vector
     */
    void encryptWithAd(const std::vector<unsigned char> &in, const std::vector<unsigned char> &ad, std::vector<unsigned char> &out);

    /**
     * @brief Decrypts and authenticates
     *
     * @param in input stream
     * @param out output stream
     */
    void decrypt(std::istream &in, std::ostream &out) override;

    /**
     * @brief Decrypts and authenticates with additional data (additional data must be supplied separately)
     *
     * @param in input stream
     * @param ad additional data stream
     * @param out output stream
     */
    void decryptWithAd(std::istream &in, std::istream &ad, std::ostream &out);

    /**
    * @brief Decrypts and authenticates with additional data (additional data must be supplied separately)
     *
     * @param in input vector
     * @param ad additional data vector
     * @param out output vector
     */
    void decryptWithAd(const std::vector<unsigned char> &in, const std::vector<unsigned char> &ad, std::vector<unsigned char> &out);
};

} //namespace helloworld

#endif //HELLOWORLD_AES_GCM_H
