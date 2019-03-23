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

#include <vector>
#include <algorithm>
#include <iostream>

namespace helloworld {

template<typename returnType, typename ... Args>
struct Callable {
    virtual ~Callable() = default;

    /**
     * Callback method
     * @param args argumens for method
     * @return <returnType> type value
     */
    virtual returnType callback(Args ... args) = 0;

    /**
     * Allows call on class pointer
     * @param callable class implementing callable
     * @param args args for callback
     * @return <returnType> type value
     */
    static returnType call(Callable *callable, Args&& ... args) {
        return callable->callback( std::forward<Args>(args)... );
    }
};


/**
 * @brief Compute file size
 *
 * @param file file to measure
 * @return file size
 */
size_t getSize(std::istream &file);

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

/**
 * Hex conversion bundle
 */
std::string &to_upper(std::string &&lowercase);

    std::string &to_lower(std::string &&uppercase);
std::string to_hex(const std::string &buff);

std::string to_hex(const std::vector<unsigned char> &bytes);

std::string to_hex(const unsigned char *bytes, size_t length);

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
 * @param array array to rewrite (format)
 * @param length length of array
 */
template<typename Obj>
void clear(Obj *array, size_t length) {
    std::fill_n(array, length, 0);
}

}

#endif //HELLOWORLD_SHARED_UTILS_H_
