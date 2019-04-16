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

struct DRState {
    DHPair DHs;    // DH Ratchet key pair (the “sending” or “self” ratchet key)
    key DHr;    // DH Ratchet public key (the “received” or “remote” key)
    key RK;            // 32-byte Root Key
    key CKs, CKr;     // 32-byte Chain Keys for sending and receiving
    size_t Ns, Nr;    // Message numbers for sending and receiving
    size_t PN;         // Number of messages in previous sending chain
    std::map<std::pair<key, size_t>, key>
        MKSKIPPED;    // Dictionary of skipped-over message keys, indexed
                       // by ratchet public key and message number. Raises an
                       // exception if too many elements are stored
    key AD;           // additional data from X3DH
};

class DoubleRatchet {
    static const int MAX_SKIP = 1000;
    DRState _state;

   private:
    DoubleRatchetAdapter ext;

    key TrySkippedMessageKeys(const MessageHeader &header,
                              const key &ciphertext, const key &hmac);
    void SkipMessageKeys(size_t until);
    void DHRatchet(const MessageHeader &header);
    std::vector<unsigned char> TryRatchetDecrypt(const Message &message);

   public:
    /**
     * @brief Create DoubleRatchetObject (RatchetInitAlice)
     *
     * @param SK shared key from X3DH exchange
     * @param other_dh_public_key Curve25519 public key from the other client
     */
    DoubleRatchet(
        std::vector<unsigned char> sk, std::vector<unsigned char> ad,
        std::vector<unsigned char> other_dh_public_key);    // RatchetInitAlice

    /**
     * @brief Create DoubleRatchetObject (RatchetInitBob)
     *
     * @param SK shared key from X3DH exchange
     * @param dh_public_key own Curve25519 public key
     * @param dh_private_key own Curve25519 public key
     */
    DoubleRatchet(std::vector<unsigned char> sk, std::vector<unsigned char> ad,
                  std::vector<unsigned char> dh_public_key,
                  std::vector<unsigned char> dh_private_key);

    /**
     * @brief Encrypts message using Double Ratchet algorithm.
     *
     * @param plaintext original message
     * @param AD additional data (output from X3DH)
     * @return Message message struct with header, hmac and ciphertext
     */
    Message RatchetEncrypt(const std::vector<unsigned char> &plaintext);

    /**
     * @brief Decrypts message using Double Ratchet algorithm
     *
     * @param message encrypted message
     * @param AD additional data (output from X3DH)
     * @return vector decrypted data
     */
    std::vector<unsigned char> RatchetDecrypt(const Message &message);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_H_
