#include "file_database.h"

#include <fstream>

#include "config.h"

using namespace helloworld;

FileDatabase::FileDatabase() {
    _source = defaultDbName;
}

FileDatabase::FileDatabase(const std::string& filename) {
    _source = filename;
}

void FileDatabase::insert(const UserData& data) {
    std::ofstream output{ _source, std::ios::binary | std::ios::app };
    if (!output)
        throw std::runtime_error("Unable to open database stream.");
    std::vector<unsigned char> length;
    std::vector<unsigned char> serialized = data.serialize();
    Serializable<UserData>::addNumeric<uint64_t>(length, serialized.size());
    output.write(reinterpret_cast<char *>(length.data()), length.size());
    output.write(reinterpret_cast<char *>(serialized.data()), serialized.size());
}

const std::vector<std::unique_ptr<helloworld::UserData>>& FileDatabase::select(const UserData& query) {
    _cache.clear();
    std::ifstream input{ _source, std::ios::binary };
    if (! input)
        throw std::runtime_error("Unable to read from database stream.");

    while (input.good() & ! input.eof()) {
        std::vector<unsigned char> length_bytes(8);
        input.read(reinterpret_cast<char *>(length_bytes.data()), sizeof(uint64_t));
        uint64_t length;
        Serializable<UserData>::getNumeric<uint64_t>(length_bytes, 0, length);
        if (length == 0)
            break;

        std::vector<unsigned char> data(length);
        input.read(reinterpret_cast<char *>(data.data()), length);
        UserData usrdata = UserData::deserialize(data);

        if ((usrdata.name.empty() || usrdata.name.find(query.name) != std::string::npos)
                && (query.id == 0 || query.id == usrdata.id)
                /*&& (query.online == data.online)*/) {
            _cache.emplace_back(std::make_unique<UserData>(usrdata));
        }
    }
    return _cache;
}

void FileDatabase::drop() {
    std::ofstream ofs;
    ofs.open(_source, std::ofstream::out | std::ofstream::trunc);
}
