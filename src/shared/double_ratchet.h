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
    static const int MAX_SKIP = 1000;
    DRState _state;
    bool _receivedMessage = false;

private:
    DoubleRatchetAdapter ext;

    std::vector<unsigned char> TrySkippedMessageKeys(const MessageHeader &header,
                              const std::vector<unsigned char> &ciphertext,
                              const std::vector<unsigned char> &hmac);
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
    DoubleRatchet(zero::bytes_t sk, zero::bytes_t ad, zero::bytes_t other_dh_public_key);    // RatchetInitAlice

    /**
     * @brief Create DoubleRatchetObject (RatchetInitBob)
     *
     * @param SK shared key from X3DH exchange
     * @param dh_public_key own Curve25519 public key
     * @param dh_private_key own Curve25519 public key
     */
    DoubleRatchet(zero::bytes_t sk,
                  zero::bytes_t ad,
                  zero::bytes_t dh_public_key,
                  zero::bytes_t dh_private_key);

    DoubleRatchet(DRState state);

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

    bool hasReceivedMessage() const {
        return _receivedMessage;
    }
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_H_
