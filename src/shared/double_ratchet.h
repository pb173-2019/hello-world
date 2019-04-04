/**
 * @file double_ratchet.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Double ratchet wrapper
 * @version 0.1
 * @date 2019-04-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_DOUBLE_RATCHET_H_
#define HELLOWORLD_SHARED_DOUBLE_RATCHET_H_

#include "double_ratchet_utils.h"

namespace helloworld {

class DoubleRatchet {
    static const int MAX_SKIP = 10;

   private:
    DoubleRatchetAdapter ext;
    DHPair _DHs;    // DH Ratchet key pair (the “sending” or “self” ratchet key)
    key _DHr;    // DH Ratchet public key (the “received” or “remote” key)
    key _RK;            // 32-byte Root Key
    key _CKs, _CKr;     // 32-byte Chain Keys for sending and receiving
    size_t _Ns, _Nr;    // Message numbers for sending and receiving
    size_t _PN;         // Number of messages in previous sending chain
    std::map<std::pair<key, size_t>, key>
        _MKSKIPPED;    // Dictionary of skipped-over message keys, indexed
                       // by ratchet public key and message number. Raises an
                       // exception if too many elements are stored

    key TrySkippedMessageKeys(const Header &header, const key &ciphertext,
                              const key &AD);
    void SkipMessageKeys(size_t until);
    void DHRatchet(const Header &header);

   public:
    DoubleRatchet(
        const std::vector<unsigned char> &sk,
        std::vector<unsigned char> other_dh_public_key);    // RatchetInitAlice
    DoubleRatchet(
        std::vector<unsigned char> sk, std::vector<unsigned char> dh_public_key,
        std::vector<unsigned char> dh_private_key);    // RatchetInitBob
    Message RatchetEncrypt(const std::vector<unsigned char> &plaintext,
                           const std::vector<unsigned char> &AD);
    std::vector<unsigned char> RatchetDecrypt(
        const Message &message, const std::vector<unsigned char> &AD);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_H_
