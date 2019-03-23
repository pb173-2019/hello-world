/**
 * @file ConnectionManager.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Connection manager takes care of
 *         - parsing the requests and responses using rrmanip.h
 *         - encryption & decryption using asymmetric cipher if no symmetric keys set (before channel establishment)
 *         - encryption & decryption using symmetric cipher if keys set (when is channel running)
 *         - key derivation, e.g. double ratchet process to derive new keys each message
 * @version 0.1
 * @date 22. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_CONNECTIONMANAGER_H_
#define HELLOWORLD_SHARED_CONNECTIONMANAGER_H_

#include <sstream>

#include "rrmanip.h"
#include "sha_512.h"
#include "rsa_2048.h"

namespace helloworld {

template <typename incoming, typename outgoing>
class ConnectionManager {

    bool _established = false;
    std::string _sessionKey;
    std::string _iv;
    std::string _macKey;

    //outgoing RSA initialized with server / user public key
    RSA2048 _rsa_out{};
    //incoming RSA initialized with server / user private key
    RSA2048 _rsa_in{};

public:
    /**
     * @brief Initialize with keys from files
     *
     * @param pubkeyFilename rsa public key of the receiver filename path
     * @param privkeyFilename rsa private key of the owner filename path
     * @param pwd password to decrypt private key
     */
    ConnectionManager(const std::string& pubkeyFilename,
            const std::string& privkeyFilename, const std::string& pwd) {
        _rsa_out.loadPublicKey(pubkeyFilename);
        _rsa_in.loadPrivateKey(privkeyFilename, getHexPwd(pwd), getHexIv(pwd));
    }

    /**
     * @brief Initialize with public key from buffer
     *
     * @param publicKeyData buffer with public key in pem format (e.g. pem file loaded into buffer)
     * @param privkeyFilename rsa private key of the owner filename path
     * @param pwd password to decrypt private key
     */
    ConnectionManager(std::vector<unsigned char>& publicKeyData,
            const std::string& privkeyFilename, const std::string& pwd) {
        _rsa_out.setPublicKey(publicKeyData);
        _rsa_in.loadPrivateKey(privkeyFilename, getHexPwd(pwd), getHexIv(pwd));
    }

    /**
     * @brief Initialize security channel pwds once the symmetric key is agreed on
     *
     * @param key symmetric key used by both sides to encrypt the first message
     * @param iv initialization vector used
     * @param macKey mac key used by both sides to verify the first message
     */
    void initializeSecurity(std::string key, std::string iv, std::string macKey) {
        _sessionKey = std::move(key);
        _iv = std::move(iv);
        _macKey = std::move(macKey);
        _established = true;
    }

    /**
     * Iv is updated every time
     *
     * @param iv
     */
    void updateIv(std::string iv) {
        _iv = std::move(iv);
    }

    /**
     * @brief Parse bytes into incoming (request/response) type structure,
     *    decrypt and verify integrity
     *
     * @param data
     * @return
     */
    incoming parseIncoming(std::stringstream &&data) {
        return {};
    }

    /**
     * @brief Parse outgoing (request/response) type structure into byte array,
     *    encrypt and add integrity check
     *
     * @param data
     * @return
     */
    std::stringstream parseOutgoing(const outgoing& data) {
        std::stringstream result;
        return result;
    }

private:
    std::string getHexPwd(const std::string& pwd) {
        return SHA512{}.getHex(Salt{"alsk5eutgahlsnd" + pwd}.get() + pwd);
    }

    std::string getHexIv(const std::string& pwd) {
        return SHA512{}.getHex(Salt{pwd + "d9fz68g54cv1as"}.get() + pwd);
    }
};

}

#endif //HELLOWORLD_SHARED_CONNECTIONMANAGER_H_
