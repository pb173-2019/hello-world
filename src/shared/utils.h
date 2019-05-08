/**
 * @file utils.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Utilities class (hex conversion, read & write utils..)
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_UTILS_H_
#define HELLOWORLD_SHARED_UTILS_H_

#include <mbedtls/include/mbedtls/bignum.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

#include "serializable_error.h"

namespace helloworld {

template <typename returnType, typename... Args>
struct Callable {
    virtual ~Callable() = default;

    /**
     * Callback method
     * @param args argumens for method
     * @return <returnType> type value
     */
    virtual returnType callback(Args... args) = 0;

    /**
     * Allows call on class pointer
     * @param callable class implementing callable
     * @param args args for callback
     * @return <returnType> type value
     */
    static returnType call(Callable *callable, Args &&... args) {
        return callable->callback(std::forward<Args>(args)...);
    }
};

class safe_mpi {
    mbedtls_mpi obj;

   public:
    safe_mpi() { mbedtls_mpi_init(&obj); }

    void reset() {
        mbedtls_mpi_free(&obj);
        mbedtls_mpi_init(&obj);
    }

    safe_mpi(const safe_mpi &o) = default;

    safe_mpi &operator=(const safe_mpi &o) = default;

    mbedtls_mpi *operator&() { return &obj; }

    ~safe_mpi() { mbedtls_mpi_free(&obj); }

    static void mpiToByteArray(const mbedtls_mpi *bigInt, unsigned char *buffer,
                               size_t len) {
        // big integer saved as int.n times value on int.p pointer
        if (mbedtls_mpi_write_binary(bigInt, buffer, len) != 0) {
            throw Error("Failed to write big integer value into buffer.");
        }
    }

    static void mpiFromByteArray(mbedtls_mpi *bigInt,
                                 const unsigned char *buffer, size_t len) {
        if (mbedtls_mpi_read_binary(bigInt, buffer, len) != 0) {
            throw Error("Failed to read big integer value from buffer.");
        }
    }
};

std::ostream &operator<<(std::ostream &out, safe_mpi &mpi);

/**
 * @brief Compute file size
 *
 * @param input input to measure
 * @return file size
 */
size_t getSize(std::istream &input);

/**
 * @brief read from input to unsigned char buffer
 *
 * @param in stream to read from
 * @param data buffer to read to
 * @param length length of buffer
 * @return length of actually read data
 */
size_t read_n(std::istream &in, unsigned char *data, size_t length);

/**
 * @brief write unsigned char buffer into ostream
 *
 * @param out stream to write to
 * @param data data to write
 * @param length length of data
 */
void write_n(std::ostream &out, const unsigned char *data, size_t length);

void write_n(std::ostream &out, const std::string &data);

void write_n(std::ostream &out, const std::vector<unsigned char> &data);

/**
 * Hex conversion bundle
 */
std::string &to_upper(std::string &&lowercase);

std::string &to_lower(std::string &&uppercase);

std::string to_hex(const std::string &buff);

std::string to_hex(const std::vector<unsigned char> &bytes);

std::string to_hex(const unsigned char bytes[], size_t length);

std::vector<unsigned char> from_hex(const std::string &input);

void from_hex(const std::string &input, unsigned char *output, size_t length);

/**
 * String <-> vector<unsigned char> conversion bundle
 */
std::vector<unsigned char> from_string(const std::string &input);

std::string to_string(const std::vector<unsigned char> &input);

/**
 * @brief Rewrite memory
 *
 * @tparam Obj array type
 * @param array pointer to array first element to rewrite (format)
 * @param length length of array in bytes
 */
template <typename T>
void clear(T *array, size_t length) {
    std::memset(array, 0, length * sizeof(T));
}

/**
 * @brief Splits vector into two vector of half the size of the original vector
 *
 * @param vector vector
 * @return std::pair<vector, vector> pair of vectors
 */
template <class T>
std::pair<std::vector<T>, std::vector<T>> split(std::vector<T> first,
                                                size_t index) {
    std::vector<T> second(first.begin() + index, first.end());
    first.resize(first.size() - second.size());

    return std::make_pair(first, second);
}

template <class T>
std::pair<std::vector<T>, std::vector<T>> split(const std::vector<T> &input) {
    return split(input, input.size() / 2);
}

/**
 * Stream - vector conversion bundle
 */
std::stringstream stream_from_vector(const std::vector<unsigned char> &vector);

std::vector<unsigned char> vector_from_stream(std::istream &stream);

/**
 * Return timestamp of specific time
 *
 * @param timer time specifier, use nullptr for 'now'
 * @return timestamp of timer
 */
uint64_t getTimestampOf(time_t *timer);

/**
 * Get any file that contains the suffix specified
 * @param suffix file suffix to search
 * @return  file with name: *suffix
 */
std::string getFile(const std::string &suffix);

std::ostream &operator<<(std::ostream &out,
                         const std::vector<unsigned char> &data);

}    // namespace helloworld

#endif    // HELLOWORLD_SHARED_UTILS_H_
