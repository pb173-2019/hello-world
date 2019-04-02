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

#include <vector>
#include <string>
#include <sstream>

#include "request_response.h"
#include "requests.h"
#include "curve_25519.h"
#include "aes_gcm.h"
#include "hkdf.h"

namespace helloworld {

class X3DH {

public:
    /**
     * Perform X3DH protocol (key exchange)
     *
     * @param pwd user password
     * @param toSend data to send
     * @param bundle key bundle of receiver fetched from server
     * @return X3DH SK key
     */
    std::string out(const std::string& pwd,
            const SendData& toSend,
            const KeyBundle<C25519> bundle,
            X3DHRequest<C25519>& toFill) {

        if (! verifyPrekey(bundle.identityKey, bundle.preKey, bundle.preKeySingiture))
            throw Error("X3DH aborted: prekey signature verification failed.");

        bool opUsed = !bundle.oneTimeKeys.empty();
        size_t keyId = 0;

        C25519KeyGen ephermalGen;
        // DH1 step
        C25519 identity;
        identity.loadPrivateKey("identityKey.key", pwd); //todo keyfilename
        identity.setPublicKey(bundle.preKey);
        std::vector<unsigned char> dh = identity.getShared();
        // DH2 step
        C25519 ephermal;
        ephermal.setPrivateKey(ephermalGen);
        ephermal.setPublicKey(bundle.identityKey);
        append(dh, ephermal.getShared());
        //DH3 step
        ephermal.setPublicKey(bundle.preKey);
        append(dh, ephermal.getShared());
        //optional DH4 step
        if (opUsed) {
            keyId = bundle.oneTimeKeys.size() - 1;
            ephermal.setPublicKey(bundle.oneTimeKeys[keyId]);
            append(dh, ephermal.getShared());
        }

        hkdf kdf;
        std::string sk = kdf.generate(to_hex(dh), 32);

        //cleanup
        if (remove("ephermal.ep") != 0) {
            throw Error("Could not delete temporary key.\n");
        }
        clear<unsigned char>(dh.data(), dh.size());

        //build request
        toFill.senderIdPubKey = std::move(loadOwnerIdKey());
        toFill.senderEphermalPubKey = std::move(ephermalGen.getPublicKey());
        toFill.opKeyUsed = opUsed ?
                X3DHRequest<C25519>::OP_KEY_USED : X3DHRequest<C25519>::OP_KEY_NONE,
        toFill.opKeyId = keyId;
        toFill.AEADenrypted = std::move(aeadEncrypt(sk, opUsed, keyId, bundle, toSend));

        return sk;
    }

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
            const KeyBundle<C25519>::signiture_t& signature) {
        C25519 c;
        //todo X3DH:: encode key signature...? but it won't work
        c.setPublicKey(identityPub);
        return c.verify(signature, prekeyPub);
    }

    /**
     * Append vector to another
     * @param to vector to append to
     * @param from vector to append
     */
    void append(std::vector<unsigned char>& to, const std::vector<unsigned char> &from) {
        to.insert(to.end(), from.begin(), from.end());
    }

    /**
     * Compute additional data stream for AESGCM
     * @param senderIdPubKey
     * @param receiverIdPubKey
     * @return additional data stream for AESGCM
     */
    std::stringstream additionalData(const std::vector<unsigned char> &senderIdPubKey,
                                const std::vector<unsigned char> &receiverIdPubKey) {
        return std::stringstream{to_hex(senderIdPubKey) + to_hex(receiverIdPubKey)};
    }

    /**
     * Load owner id key from file created on registration
     * @return vector with raw bytes of public key
     */
    std::vector<unsigned char> loadOwnerIdKey() {
        std::ifstream input{"identityKey.pub", std::ios::in | std::ios::binary};
        if (!input)
            throw Error("Could not load user public key.");
        std::vector<unsigned char> key(C25519::KEY_BYTES_LEN);
        read_n(input, key.data(), key.size());
        return key;
    }

    /**
     * Compute AESGCM with AD from data send by user
     * @param key key to use for encryption, sould be the result of
     *        KDF( DH1 || DH2 || DH3 || DH4 - optionally)
     * @param opKeyUsed whether the DH4 was used or not
     * @param opKeyId id in vector of the op key used for DH4
     * @param bundle bundle with receiver X3DH keys
     * @param data data to encrypt
     * @return encrypted data vector
     */
    std::vector<unsigned char> aeadEncrypt(const std::string& key,
            bool opKeyUsed,
            size_t opKeyId,
            const KeyBundle<C25519>& bundle,
            const SendData& data) {

        AESGCM gcm;
        gcm.setKey(key);

        //prekey used as IV if no onetime keys
        if (opKeyUsed) gcm.setIv(to_hex(bundle.oneTimeKeys[opKeyId]).substr(0, 32));
        else gcm.setIv(to_hex(bundle.preKey).substr(0, 32));

        std::stringstream toEncrypt{};
        std::stringstream result{};
        std::stringstream ad = additionalData(loadOwnerIdKey(), bundle.identityKey);
        write_n(toEncrypt, data.serialize());

        gcm.encryptWithAd(toEncrypt, ad, result);
        size_t size = getSize(result);
        std::vector<unsigned char> resultBytes(size);
        size_t read = read_n(result, resultBytes.data(), size);
        if (read != size)
            throw Error("X3DH: Could not read AEAD encrypted stream.");
        return resultBytes;
    }
};


} //namespace helloworld


#endif //HELLOWORLD_CURVE_25519_H
