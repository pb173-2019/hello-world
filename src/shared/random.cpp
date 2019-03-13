#include "random.h"

#include <stdexcept>
#include <cmath>

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include <winbase.h>
#include <iostream>

#else
// todo linux
#endif

namespace helloworld {

    Random::Random() {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        unsigned char salt[16];
        getSeedEntropy(salt);

        if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, salt, 16) != 0) {
            throw std::runtime_error("Could not init seed.");
        }
        mbedtls_ctr_drbg_set_prediction_resistance(&_ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);
    }


    std::vector<unsigned char> Random::get(size_t size) {
        //todo clear memory, used for key generators
        //todo or better, move data from array to vector
        unsigned char data[size];

        if (mbedtls_ctr_drbg_random(&_ctr_drbg, data, size) != 0) {
            throw std::runtime_error("Could not generate random sequence.");
        }
        std::vector<unsigned char> result(data, data + size);

        //addresses different! copied - insecure
        std::cout << static_cast<const void *>(data) << "\n";
        std::cout << static_cast<const void *>(result.data()) << "\n";
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

    void Random::getSeedEntropy(unsigned char *buff) {

#if defined(WINDOWS)
        MEMORYSTATUS lpBuffer;
        POINT lpPoint;
        SYSTEM_INFO lpSystemInfo;
        GlobalMemoryStatus(&lpBuffer);
        GetCursorPos(&lpPoint);
        GetSystemInfo(&lpSystemInfo);

        buff[1] = static_cast<unsigned char>(lpBuffer.dwAvailPageFile);
        buff[6] = static_cast<unsigned char>(lpBuffer.dwAvailPhys);
        buff[12] = static_cast<unsigned char>(lpBuffer.dwAvailVirtual);
        buff[4] = static_cast<unsigned char>(lpBuffer.dwLength);
        buff[13] = static_cast<unsigned char>(lpBuffer.dwMemoryLoad);
        buff[2] = static_cast<unsigned char>(lpBuffer.dwTotalPageFile);
        buff[15] = static_cast<unsigned char>(lpBuffer.dwTotalVirtual);
        buff[9] = static_cast<unsigned char>(lpBuffer.dwTotalPhys);
        buff[8] = static_cast<unsigned char>(lpPoint.x);
        buff[3] = static_cast<unsigned char>(lpPoint.y);
        buff[10] = static_cast<unsigned char>(lpSystemInfo.dwProcessorType);
        buff[11] = static_cast<unsigned char>(lpSystemInfo.dwActiveProcessorMask);
        buff[5] = static_cast<unsigned char>(lpSystemInfo.wProcessorArchitecture);
        buff[7] = static_cast<unsigned char>(lpSystemInfo.wProcessorRevision);
        buff[14] = static_cast<unsigned char>(lpSystemInfo.wReserved);
        std::cout << "Entropy: ";
        for (int i = 0; i < 16; i++) {
            std::cout << buff[i] << ", ";
        }
        std::cout << "\n";
#else
        //todo linux
#endif
    }
}
