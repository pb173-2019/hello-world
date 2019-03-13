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
#include <iostream>

namespace helloworld {

size_t read_n(std::istream &in, unsigned char *data, size_t length);

void write_n(std::ostream &out, unsigned char *data, size_t length);

std::string to_upper(std::string lowercase);

std::string to_hex(const std::string& buff);

std::string to_hex(const std::vector<unsigned char> &bytes);

std::string to_hex(const unsigned char *bytes, size_t length);

std::vector<unsigned char> from_hex(const std::string &input);

void from_hex(const std::string &input, unsigned char* output, size_t length);

std::vector<unsigned char> from_string(const std::string& input);

std::string to_string(const std::vector<unsigned char>& input);

}

#endif //HELLOWORLD_SHARED_UTILS_H_
