#include <iomanip>
#include <sstream>
#include <algorithm>
#include <ctime>

#include "utils.h"
#include "serializable_error.h"

#if defined(WINDOWS)
#include <windows.h>
#include <io.h>

#else

#include <dirent.h>

#endif

namespace helloworld {

std::ostream &operator<<(std::ostream &out, safe_mpi &mpi) {
    out << "mpi: ";
    std::vector<unsigned char> buffer(32);
    mbedtls_mpi_write_binary(&mpi, buffer.data(), buffer.size());
    for (auto value : buffer) {
        out << static_cast<int>(value) << '.';
    }
    out << " |\n";
    return out;
}

size_t getSize(std::istream &input) {
    auto original = input.tellg();
    input.seekg(0, std::ios::end);
    auto delta = static_cast<size_t >(input.tellg() - original);
    input.seekg(original);
    return delta;
}

size_t read_n(std::istream &in, unsigned char *data, size_t length) {
    in.read(reinterpret_cast<char *>(data), length);
    return static_cast<size_t>(in.gcount());
}

void write_n(std::ostream &out, const unsigned char *data, size_t length) {
    out.write(reinterpret_cast<const char *>(data), length);
}

void write_n(std::ostream &out, const std::string &data) {
    write_n(out, reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

void write_n(std::ostream &out, const std::vector<unsigned char> &data) {
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
    return to_hex(reinterpret_cast<const unsigned char *>(buff.data()), buff.length());
}

std::string to_hex(const std::vector<unsigned char> &bytes) {
    return to_hex(bytes.data(), bytes.size());
}

std::string to_hex(const unsigned char bytes[], size_t length) {
    std::stringstream stream;
    for (size_t i = 0; i < length; i++) {
        stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return stream.str();
}

void from_hex(const std::string &input, unsigned char *output, size_t length) {
    if (input.size() != length * 2) {
        throw Error("Invalid conversion dimensions.");
    }
    std::vector<unsigned char> vector = from_hex(input);
    std::copy_n(vector.data(), length, output);
}

std::vector<unsigned char> from_hex(const std::string &input) {
    std::vector<unsigned char> vector;

    size_t len = input.length();
    for (size_t i = 0; i < len; i += 2) {
        std::stringstream x{input.substr(i, 2)};
        unsigned int c;
        x >> std::hex >> c;
        vector.push_back(static_cast<unsigned char &&>(c));
    }
    return vector;
}

std::vector<unsigned char> from_string(const std::string &input) {
    return std::vector<unsigned char>(input.begin(), input.end());
}

std::string to_string(const std::vector<unsigned char> &input) {
    return std::string(input.begin(), input.end());
}

uint64_t getTimestampOf(time_t *timer) {
    std::time_t t = std::time(timer);
    std::tm *lt = std::localtime(&t);
    return static_cast<uint64_t>(lt->tm_year * 366 * 24 + lt->tm_yday * 24 + lt->tm_hour);
}

std::stringstream stream_from_vector(const std::vector<unsigned char> &vector) {
    std::stringstream stream;
    write_n(stream, vector);
    return stream;
}

std::vector<unsigned char> vector_from_stream(std::istream &stream) {
    size_t size = getSize(stream);
    std::vector<unsigned char> result(size);
    size_t read = read_n(stream, result.data(), size);
    if (read != size) {
        throw Error("Could not read stream.");
    }
    return result;
}

std::string getFile(const std::string &suffix) {
    std::string file;

#if defined(WINDOWS)
    //from https://stackoverflow.com/questions/11140483/how-to-get-list-of-files-with-a-specific-extension-in-a-given-folder

    WIN32_FIND_DATAA data;
    HANDLE handle = FindFirstFile(".\\*", &data);

    if (handle) {
        do {
            if (std::strstr(data.cFileName, suffix.c_str())) {
                file = data.cFileName;
                break;
            }
        } while ( FindNextFile(handle, &data));
        FindClose(handle);
    }

#else

    DIR *dirFile = opendir(".");
    if (dirFile) {
        struct dirent *hFile;
        errno = 0;
        while ((hFile = readdir(dirFile)) != nullptr) {
            if (std::strstr(hFile->d_name, suffix.c_str())) {
                file = hFile->d_name;
                break;
            }
        }
        closedir(dirFile);
    }

#endif

    return file;
}

std::ostream& operator<<(std::ostream& out, const std::vector<unsigned char> & data) {
    for (auto& c : data) {
        out << static_cast<int>(c) << ",";
    }
    out << "\n";
    return out;
}


} //namespace helloworld
