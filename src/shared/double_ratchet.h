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

#include <map>

namespace helloworld {

struct Header {
    int dh;
    int pn;
    int n;
};

struct Message {
    Header header;
    int payload;
};

class DoubleRatchet {
    static const int MAX_SKIP = 10;

   private:
    int _DHs;    // DH Ratchet key pair (the “sending” or “self” ratchet key)
    int _DHr;    // DH Ratchet public key (the “received” or “remote” key)
    int _RK;           // 32-byte Root Key
    int _CKs, _CKr;    // 32-byte Chain Keys for sending and receiving
    int _Ns, _Nr;      // Message numbers for sending and receiving
    int _PN;           // Number of messages in previous sending chain
    std::map<std::pair<int, int>, int>
        _MKSKIPPED;    // Dictionary of skipped-over message keys, indexed
                       // byratchet public key and message number. Raises an
                       // exception if too manyelements are stored
    int GENERATE_DH();
    int DH(int dh_pair, int dh_pub);
    std::pair<int, int> KDF_RK(int rk, int dh_out);
    std::pair<int, int> KDF_CK(int ck);
    int ENCRYPT(int mk, int plaintext, int associated_data);
    int DECRYPT(int mk, int ciphertext, int associated_data);
    Header HEADER(int dh_pair, int pn, int n);
    int CONCAT(int ad, const Header &header);
    
    int TrySkippedMessageKeys(const Header &header, int ciphertext, int AD);
    int SkipMessageKeys(int until);
    void DHRatchet(const Header &header);

   public:
    DoubleRatchet(int sk, int bob_dh_public_key);     // RatchetInitAlice
    DoubleRatchet(int sk, size_t bob_dh_key_pair);    // RatchetInitBob
    Message RatchetEncrypt(int plaintext, int AD);
    int RatchetDecrypt(const Header &header, int ciphertext, int AD);
};

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_DOUBLE_RATCHET_H_
