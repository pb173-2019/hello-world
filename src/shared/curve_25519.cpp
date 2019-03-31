#include "curve_25519.h"

extern "C" {
#include "ed25519/keygen.h"
#include "ed25519/ge.h"
#include "ed25519/crypto_additions.h"
#include "ed25519/fe.h"
}

namespace helloworld {

    C25519KeyGen::C25519KeyGen() {
        Random random{};

        _buffer_public.resize(KEY_BYTES_LEN);

        _buffer_private = random.get(KEY_BYTES_LEN);
        sc_clamp(_buffer_private.data());

        curve25519_keygen(_buffer_public.data(), _buffer_private.data());
    }


    bool C25519KeyGen::savePrivateKey(const std::string &filename, const std::string &key, const std::string &iv) {
        std::ofstream out_pri{filename, std::ios::out | std::ios::binary};
        if (!out_pri)
            return false;

        if (!key.empty()) {
            std::stringstream keystream{};
            AES128 cipher{};
            write_n(keystream, _buffer_private);
            cipher.setKey(key);
            cipher.setIv(iv);
            cipher.encrypt(keystream, out_pri);
        } else {
            write_n(out_pri, _buffer_private);
        }
        return true;
    }

    bool C25519KeyGen::savePrivateKeyPassword(const std::string &filename, const std::string &pwd) {
        return savePrivateKey(filename, getHexPwd(pwd), getHexIv(pwd));
    }

    bool C25519KeyGen::savePublicKey(const std::string &filename) const {
        std::ofstream out_pub{filename, std::ios::out | std::ios::binary};
        if (!out_pub)
            return false;

        write_n(out_pub, _buffer_public);
        return true;
    }

    std::vector<unsigned char> C25519KeyGen::getPublicKey() const {
        return _buffer_public;
    }


    C25519::C25519() = default;

    void C25519::setPublicKey(const std::vector<unsigned char> &key) {
        if (key.size() != KEY_BYTES_LEN) //works with X only
            throw Error("Invalid c25519 public key.");
        _buffer_public = key;
        _setup(KeyType::PUBLIC_KEY);
    }

    void C25519::loadPublicKey(const std::string &keyFile) {
        std::ifstream input{keyFile, std::ios::in | std::ios::binary};
        if (!input) return;
        _buffer_public.resize(KEY_BYTES_LEN);
        read_n(input, _buffer_public.data(), KEY_BYTES_LEN);
        _setup(KeyType::PUBLIC_KEY);
    }

    void C25519::loadPrivateKey(const std::string &keyFile, const std::string &key, const std::string &iv) {
        std::ifstream input{keyFile, std::ios::in | std::ios::binary};
        if (!input) return;

        _buffer_private.resize(KEY_BYTES_LEN);
        if (!key.empty()) {
            std::stringstream decrypted;
            AES128 cipher;
            cipher.setIv(iv);
            cipher.setKey(key);
            cipher.decrypt(input, decrypted);
            read_n(decrypted, _buffer_private.data(), _buffer_private.size());
        } else {
            read_n(input, _buffer_private.data(), _buffer_private.size());
        }
        _setup(KeyType::PRIVATE_KEY);
    }

    void C25519::loadPrivateKey(const std::string &keyFile, const std::string &pwd) {
        loadPrivateKey(keyFile, C25519KeyGen::getHexPwd(pwd), C25519KeyGen::getHexIv(pwd));
    }

    mbedtls_mpi toMpi(const unsigned char* buff, size_t len) {
        mbedtls_mpi a;
        mbedtls_mpi_init(&a);
        C25519KeyGen::mpiFromByteArray(&a, buff, len);
        return a;
    }

    std::vector<unsigned char>X25519(const std::vector<unsigned char>& key,
                                     const std::vector<unsigned char>& d,
                                     const mbedtls_ecdh_context& _context) {
        mbedtls_mpi k = toMpi(key.data(), key.size());
        mbedtls_mpi Exp2; mbedtls_mpi_init(&Exp2);
        mbedtls_mpi_lset(&Exp2, 2);

        mbedtls_mpi x_1 = toMpi(d.data(), d.size());
        mbedtls_mpi x_2; mbedtls_mpi_init(&x_2);
        mbedtls_mpi_lset(&x_2, 1);
        mbedtls_mpi x_3 = toMpi(d.data(), d.size());
        mbedtls_mpi z_2; mbedtls_mpi_init(&z_2);
        mbedtls_mpi_lset(&z_2, 0);
        mbedtls_mpi z_3; mbedtls_mpi_init(&z_3);
        mbedtls_mpi_lset(&z_3, 1);
        int swap = 0;

        for (int i = 255; i >= 0; i--) {
            //todo possibly get ith bit
            mbedtls_mpi temp_k; mbedtls_mpi_init(&temp_k);
            mbedtls_mpi_copy(&temp_k, &k);
            mbedtls_mpi_shift_r(&k, i);
            int lastBit = mbedtls_mpi_get_bit(&temp_k, 0);
            //cond swap
            swap ^= lastBit;
            mbedtls_mpi_safe_cond_swap(&x_2, &x_3, swap);
            mbedtls_mpi_safe_cond_swap(&z_2, &z_3, swap);
            swap = lastBit;
            // A = X_2 + Z_2
            mbedtls_mpi A; mbedtls_mpi_init(&A);
            mbedtls_mpi_add_mpi(&A, &x_2, &z_2);
            //A^2
            mbedtls_mpi AA; mbedtls_mpi_init(&AA);
            mbedtls_mpi_exp_mod(&AA, &A, &Exp2, &_context.grp.P, nullptr);
            // B = x_2 - z_2
            mbedtls_mpi B; mbedtls_mpi_init(&B);
            mbedtls_mpi_sub_mpi(&B, &x_2, &z_2);
            //B^2
            mbedtls_mpi BB; mbedtls_mpi_init(&BB);
            mbedtls_mpi_exp_mod(&BB, &B, &Exp2, &_context.grp.P, nullptr);
            // E = AA - BB
            mbedtls_mpi E; mbedtls_mpi_init(&E);
            mbedtls_mpi_sub_mpi(&E, &AA, &BB);
            // C = x_3 + z_3
            mbedtls_mpi C; mbedtls_mpi_init(&C);
            mbedtls_mpi_add_mpi(&C, &x_3, &z_3);
            // D = x_3 - z_3
            mbedtls_mpi D; mbedtls_mpi_init(&D);
            mbedtls_mpi_sub_mpi(&D, &x_3, &z_3);
            // DA = D * A
            mbedtls_mpi DA; mbedtls_mpi_init(&DA);
            mbedtls_mpi_mul_mpi(&DA, &D, &A);
            //CB = C * B
            mbedtls_mpi CB; mbedtls_mpi_init(&CB);
            mbedtls_mpi_mul_mpi(&CB, &C, &B);
            //x_3 = (DA + CB)^2
            mbedtls_mpi tmp; mbedtls_mpi_init(&tmp);
            mbedtls_mpi_add_mpi(&tmp, &DA, &CB);
            mbedtls_mpi_exp_mod(&x_3, &tmp, &Exp2, &_context.grp.P, nullptr);
            mbedtls_mpi_free(&tmp);
            //z_3 = x_1 * (DA - CB)^2
            mbedtls_mpi_init(&tmp);
            mbedtls_mpi tmp2; mbedtls_mpi_init(&tmp2);
            mbedtls_mpi_sub_mpi(&tmp, &DA, &CB);
            mbedtls_mpi_exp_mod(&tmp2, &tmp, &Exp2, &_context.grp.P, nullptr);
            mbedtls_mpi_mul_mpi(&z_3, &x_1, &tmp2);
            mbedtls_mpi_free(&tmp); mbedtls_mpi_free(&tmp2);
            //x_2 = AA * BB
            mbedtls_mpi_mul_mpi(&x_2, &AA, &BB);
            //z_2 = E * (AA + a24 * E)
            mbedtls_mpi_init(&tmp); mbedtls_mpi_init(&tmp2);
            mbedtls_mpi_mul_int(&tmp, &E, 121665 /*a24*/);
            mbedtls_mpi_add_mpi(&tmp2, &AA, &tmp);
            mbedtls_mpi_mul_mpi(&z_2, &E, &tmp2);
            mbedtls_mpi_free(&tmp); mbedtls_mpi_free(&tmp2);
        }
        mbedtls_mpi_safe_cond_swap(&x_2, &x_3, swap);
        mbedtls_mpi_safe_cond_swap(&z_2, &z_3, swap);

        // Return x_2 * (z_2^(p - 2))
        mbedtls_mpi tmp; mbedtls_mpi_init(&tmp);
        mbedtls_mpi_sub_int(&tmp, &_context.grp.P, 2);
        mbedtls_mpi tmp2; mbedtls_mpi_init(&tmp2);
        mbedtls_mpi_exp_mod(&tmp2, &z_2, &tmp, &_context.grp.P, nullptr);

        mbedtls_mpi result; mbedtls_mpi_init(&result);
        mbedtls_mpi_mul_mpi(&result, &x_2, &tmp2);

        std::vector<unsigned char> buffer(32);
        mbedtls_mpi_write_binary(&result, buffer.data(), buffer.size());
        return buffer;
    }

    std::vector<unsigned char> C25519::getShared() {
        if (!_valid())
            throw Error("C25519 not initialized properly.");


        mbedtls_ecdh_context _context;
        mbedtls_ecdh_init(&_context);
        if (mbedtls_ecp_group_load(&_context.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
            throw Error("Could not load CURVE25519 to context.");
        }

        std::vector<unsigned char> temp = X25519(_buffer_private, {9}, _context);
        return X25519(_buffer_public, temp, _context);
    }

    bool C25519::_valid() {
        return (_flags & 0x03) == 0x03;
    }

    void C25519::_setup(KeyType type) {
        switch (type) {
            case KeyType::NO_KEY:
                _flags = 0x00;
                break;
            case KeyType::PRIVATE_KEY:
                _flags |= 0x01;
                break;
            case KeyType::PUBLIC_KEY:
                _flags |= 0x02;
                break;
        }
    }

} //namespace helloworld
