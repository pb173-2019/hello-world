#include "random.h"

#include <cmath>
#include <cstring>

#include "serializable_error.h"
#include "utils.h"

#if defined(WINDOWS)

// clang-format off
#include <windows.h>
#include <wincrypt.h>
#include <winbase.h>
// clang-format on

#else
#include <fstream>
#endif

namespace helloworld {
std::mutex Random::_mutex;

mbedtls_entropy_context Random::_entropy{};
mbedtls_ctr_drbg_context Random::_ctr_drbg{};
size_t Random::_instance_counter = 0;
size_t Random::_use_since_reseed = SIZE_MAX;

Random::Random() {
    std::unique_lock<std::mutex> lock(_mutex);
    _init();
    ++_instance_counter;
}

std::vector<unsigned char> Random::get(size_t size) {
    std::unique_lock<std::mutex> lock(_mutex);
    if (_use_since_reseed >= RESEED_AFTER) _reseed();
    std::vector<unsigned char> result(size);
    if (mbedtls_ctr_drbg_random(&_ctr_drbg, result.data(), result.size()) !=
        0) {
        throw Error("Could not generate random sequence.");
    }
    return result;
}

zero::bytes_t Random::getKey(size_t size) {
    std::unique_lock<std::mutex> lock(_mutex);
    zero::bytes_t key(size);
    if (mbedtls_ctr_drbg_random(&_ctr_drbg, key.data(), key.size()) != 0) {
        throw Error("Could not generate random sequence.");
    }
    return key;
}

size_t Random::getBounded(size_t lower, size_t upper) {
    size_t result = 0;
    {
        std::unique_lock<std::mutex> lock(_mutex);

        if (_use_since_reseed >= RESEED_AFTER) _reseed();

        unsigned char data[3];

        if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, 3) != 0) {
            throw Error("Could not generate random sequence.");
        }

        for (int i = 0; i < 3; i++) {
            result += static_cast<size_t>(std::pow(255, i)) * data[i];
        }
    }    // prevents deadlock when recursively called

    result = result % upper;
    if (result >= lower) {
        return result;
    } else {
        return getBounded(lower, upper);
    }
}

mbedtls_ctr_drbg_context *Random::getEngine() { return &_ctr_drbg; }

std::unique_lock<std::mutex> Random::lock() {
    return std::unique_lock<std::mutex>(_mutex);
}

Random::~Random() {
    --_instance_counter;
    if (!_instance_counter) {
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_entropy_free(&_entropy);
        // Not necessary, but might be safer
        _use_since_reseed = SIZE_MAX;
    }
}

void Random::_getSeedEntropy(unsigned char *buff) {
#if defined(WINDOWS)
    // used as advised in
    // https://tls.mbed.org/kb/how-to/add-entropy-sources-to-entropy-pool CSP
    // used: PROV_RSA_FULL alternatives:
    //  PROV_RSA_AES
    //  PROV_RSA_SIG
    //  PROV_DSS
    //  PROV_DSS_DH
    //  PROV_SSL
    // 0 considered as fail !

    HCRYPTPROV hCryptProv;

    if (CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL, 0) ==
        0) {
        DWORD err = GetLastError();
        if (err == NTE_BAD_KEYSET &&
            CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_FULL,
                                CRYPT_NEWKEYSET) == 0) {
            throw Error(
                "Could not initialize crypt context of windows system.");
        }
        throw Error(("Windows error code: " + std::to_string(err) +
                     ", could not initialize cipher context."));
    }

    if (!CryptGenRandom(hCryptProv, 16, buff)) {
        throw Error("Could not get entropy source of windows system.");
    }

    if (!CryptReleaseContext(hCryptProv, 0)) {
        throw Error("Failed to release cipher context of windows system.");
    }
#else
    std::ifstream randomSource("/dev/urandom");
    if (!randomSource) throw Error("Couldn't acquire entropy");
    randomSource.read(reinterpret_cast<char *>(buff), 16);    // NOLINT
#endif
}

void Random::_init() {
    if (!_instance_counter) {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        unsigned char salt[16];
        _getSeedEntropy(salt);

        if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                                  salt, 16) != 0) {
            throw Error("Could not init seed.");
        }
        mbedtls_ctr_drbg_set_prediction_resistance(&_ctr_drbg,
                                                   MBEDTLS_CTR_DRBG_PR_ON);
        _use_since_reseed = 0;
    }
}

void Random::_reseed() {
    unsigned char salt[16];
    _getSeedEntropy(salt);
    if (mbedtls_ctr_drbg_reseed(&_ctr_drbg, salt, 16) != 0) {
        throw Error("Could not reseed.");
    }
    _use_since_reseed = 0;
}

}    // namespace helloworld
