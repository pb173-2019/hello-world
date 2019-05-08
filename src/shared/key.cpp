#include "key.h"

#include "utils.h"
#include <iomanip>

namespace helloworld {
    namespace zero {
        bytes_t from_hex_safe(const str_t &input) {
            bytes_t vector;
            std::string temp{input.data(), input.size()};

            size_t len = input.length();
            for (size_t i = 0; i < len; i += 2) {
                std::stringstream x{temp.substr(i, 2)};
                unsigned int c;
                x >> std::hex >> c;
                vector.push_back(static_cast<unsigned char &&>(c));
                x.seekg(0);
                x << '\0' << '\0';
            }
            //TODO enable! it tries to pass as const char
            //clear<const char>(temp.data(), temp.size());
            return vector;
        }

        bytes_t from_hex(const str_t &input) {
            return from_hex_safe(input);
        }

        str_t to_hex_safe(const unsigned char bytes[], size_t length) {
            std::stringstream stream;
            for (size_t i = 0; i < length; i++) {
                stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
            }
            std::string data = stream.str();
            stream.seekg(0);
            for (size_t j = 0; j < length; j++) {
                stream << '\0' << '\0';
            }
            str_t result{data.data(), data.size()};
            //TODO enable!
            //clear<char>(data.begin(), data.size());
            return result;
        }

        str_t to_hex(const bytes_t &bytes) {
            return to_hex_safe(bytes.data(), bytes.size());
        }

        std::pair<bytes_t, bytes_t> split(bytes_t first, size_t index) {
            bytes_t second(first.begin() + index, first.end());
            first.resize(first.size() - second.size());

            return std::make_pair(first, second);
        }

        std::pair<bytes_t, bytes_t> split(const bytes_t &input) {
            return split(input, input.size() / 2);
        }

        void write_n(std::ostream &out, const str_t &data) {
            out.write(data.data(), data.size());
        }

        void write_n(std::ostream &out, const bytes_t &data) {
            out.write(reinterpret_cast<const char *>(data.data()), data.size());
        }
    } // namespace zero
} // namespace helloworld
