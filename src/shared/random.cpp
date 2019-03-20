#include "random.h"

#include <stdexcept>
#include <cmath>

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include <winbase.h>

#else
#include <fstream>
#endif

namespace helloworld {

    Random::Random() {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        unsigned char salt[16];
        _getSeedEntropy(salt);

        if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, salt, 16) != 0) {
            throw std::runtime_error("Could not init seed.");
        }
        mbedtls_ctr_drbg_set_prediction_resistance(&_ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);
    }

    std::vector<unsigned char> Random::get(size_t size) {
        std::vector<unsigned char> result(size);
        if (mbedtls_ctr_drbg_random(&_ctr_drbg, result.data(), result.size()) != 0) {
            throw std::runtime_error("Could not generate random sequence.");
        }
        return result;
    }

    size_t Random::getBounded(size_t lower, size_t upper) {
        unsigned char data[3];
        if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, 3) != 0) {
            throw std::runtime_error("Could not generate random sequence.");
        }

        size_t result = 0;
        for (int i = 0; i < 3; i++) {
            result += static_cast<size_t>(std::pow(255, i)) * data[i];
        }

        result = result % upper;
        if (result >= lower) {
            return result;
        } else {
            return getBounded(lower, upper);
        }
    }

    mbedtls_ctr_drbg_context *Random::getEngine() {
        return &_ctr_drbg;
    }

    Random::~Random() {
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_entropy_free(&_entropy);
    }

    void Random::_getSeedEntropy(unsigned char *buff) {

#if defined(WINDOWS)
        //used as advised in https://tls.mbed.org/kb/how-to/add-entropy-sources-to-entropy-pool
        //CSP used: PROV_RSA_FULL
        //alternatives:
        //  PROV_RSA_AES
        //  PROV_RSA_SIG
        //  PROV_DSS
        //  PROV_DSS_DH
        //  PROV_SSL
        // 0 considered as fail !

        HCRYPTPROV   hCryptProv;

        if (CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0) == 0) {
            DWORD err = GetLastError();
            if (err == NTE_BAD_KEYSET && CryptAcquireContext(&hCryptProv, nullptr, nullptr,
                    PROV_RSA_FULL, CRYPT_NEWKEYSET) == 0) {
                throw std::runtime_error("Could not initialize crypt context of windows system.");
            }
            throw std::runtime_error("Windows error code: " + std::to_string(err) +
                                     ", could not initialize cipher context.");
        }

        if(! CryptGenRandom(hCryptProv, 16, buff)) {
            throw std::runtime_error("Could not get entropy source of windows system.");
        }

        if(!CryptReleaseContext(hCryptProv, 0)) {
            throw std::runtime_error("Failed to release cipher context of windows system.");
        }
#else
        std::ifstream randomSource("/dev/urandom");
        if (!randomSource)
            throw std::runtime_error("Couldn't acquire entropy");
        randomSource.read(reinterpret_cast<char *>(buff), 16); //NOLINT
#endif
    }
}
