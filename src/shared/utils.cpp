#include <iomanip>
#include <sstream>
#include <algorithm>

#include "utils.h"
#include "serializable_error.h"

namespace helloworld {

size_t getSize(std::istream &input) {
    auto original = input.tellg();
    input.seekg(0, std::ios::end);
    auto delta = static_cast<size_t >(input.tellg() - original);
    input.seekg(original);
    return delta;
}

size_t read_n(std::istream &in, unsigned char *data, size_t length) {
    in.read((char *) data, length);
    return static_cast<size_t>(in.gcount());
}

void write_n(std::ostream &out, const unsigned char *data, size_t length) {
    out.write((char *) data, length);
}

void write_n(std::ostream &out, const std::string& data) {
    write_n(out, reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

void write_n(std::ostream &out, const std::vector<unsigned char>& data) {
    write_n(out, data.data(), data.size());
}

std::string &to_upper(std::string &&lowercase) {
    std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::toupper);
    return lowercase;
}

    std::string &to_lower(std::string &&uppercase) {
        std::transform(uppercase.begin(), uppercase.end(), uppercase.begin(), ::tolower);
        return uppercase;
    }

std::string to_hex(const std::string &buff) {
    return to_hex((const unsigned char *) buff.data(), buff.length());
}

std::string to_hex(const std::vector<unsigned char> &bytes) {
    return to_hex(bytes.data(), bytes.size());
}

std::string to_hex(const unsigned char bytes[], size_t length) {
    std::stringstream stream;
    for (size_t i = 0; i < length; i++) {
        stream << std::hex << std::setfill('0') << std::setw(2) << (int) (bytes[i]);
    }
    return stream.str();
}

void from_hex(const std::string &input, unsigned char *output, size_t length) {
    if (input.size() != length * 2) {
        throw Error("Invalid conversion dimensions.");
    }
    std::vector<unsigned char> vector = from_hex(input);
    //todo too much copying
    std::copy_n(vector.data(), length, output);
    clear<unsigned char>(vector.data(), vector.size());
}

std::vector<unsigned char> from_hex(const std::string &input) {
    std::vector<unsigned char> vector;

    size_t len = input.length();
    for (size_t i = 0; i < len; i += 2) {
        std::stringstream x{input.substr(i, 2)};
        unsigned int c;
        x >> std::hex >> c;
        vector.push_back(c);
    }
    return vector;
}

std::vector<unsigned char> from_string(const std::string &input) {
    return std::vector<unsigned char>(input.begin(), input.end());
}

std::string to_string(const std::vector<unsigned char> &input) {
    return std::string(input.begin(), input.end());
}

} //namespace helloworld
