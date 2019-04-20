/**
 * @file x3dh.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief mbedTLS wrapper for ECDH 25519
 * @version 0.1
 * @date 29. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_X3DH_H_
#define HELLOWORLD_SHARED_X3DH_H_

#include <sstream>
#include <string>
#include <vector>
#include <iostream>

#include "../client/config.h"

#include "aes_gcm.h"
#include "curve_25519.h"
#include "hkdf.h"
#include "request_response.h"
#include "requests.h"


namespace helloworld {

class X3DH {
    const std::string& username;
    const std::string& pwd;
    uint64_t timestamp = 0;

public:
    struct X3DHSecretPubKey {
        std::vector<unsigned char> sk;
        std::vector<unsigned char> ad;
        std::vector<unsigned char> pubKey;
    };

    struct X3DHSecretKeyPair {
        std::vector<unsigned char> sk;
        std::vector<unsigned char> ad;
        std::vector<unsigned char> pubKey;
        std::vector<unsigned char> privKey;
    };

    X3DH(const std::string& username, const std::string& pwd)
        : username(username), pwd(pwd) {}

    void setTimestamp(uint64_t timestamp) { this->timestamp = timestamp; }

    /**
     * Perform the second part of the X3DH protocol
     * 
     * @param incoming incoming request, generated with sendInitialMessage() method
     * @return encrypted data for ratchet, and the shared secret output
     */
    std::pair<std::vector<unsigned char>, X3DHSecretKeyPair> getSecret(const Response& incoming);

    /**
     * Perform the first part of the X3DH protocol
     * @param bundle key bundle fetched from the server
     * @return std::pair<X3DHRequest<C25519>, X3DHSecretPubKey> returns key set needed for the second X3DH part
     */
    std::pair<X3DHRequest<C25519>, X3DHSecretPubKey> setSecret(
        const KeyBundle<C25519>& bundle) const;

private:
    /**
     * Verify signature on prekey used
     *
     * @param identityPub identity public key of the receiver
     * @param prekeyPub identity prekey of the receiver
     * @param signature signature of the prekeyPub
     * @return true if verified
     */
    bool verifyPrekey(const KeyBundle<C25519>::key_t& identityPub,
                      const KeyBundle<C25519>::key_t& prekeyPub,
                      const KeyBundle<C25519>::signiture_t& signature) const;

    /**
     * Append vector to another
     * @param to vector to append to
     * @param from vector to append
     */
    void append(std::vector<unsigned char>& to,
                const std::vector<unsigned char>& from) const;

    /**
     * Load owner id key from file created on registration
     * @return vector with raw bytes of public key
     */
    std::vector<unsigned char> loadC25519Key(
        const std::string& filename) const;

};

}    // namespace helloworld

#endif    // HELLOWORLD_X3DH_H
