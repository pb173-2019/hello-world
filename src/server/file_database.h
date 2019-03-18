/**
 * @file file_database.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Database file implementation
 * @version 0.1
 * @date 16. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_FILE_DATABASE_H_
#define HELLOWORLD_SERVER_FILE_DATABASE_H_

#include <cstdint>

#include "database.h"

class FileDatabase : public Database {

    std::string source;
    uint32_t lastSearchedId = 0;
    std::string lastSearched;
    std::vector<std::unique_ptr<helloworld::UserData>> cache;

public:
    FileDatabase();

    FileDatabase(const std::string& filename);

    // Copying is not available
    FileDatabase(const FileDatabase &other) = delete;

    FileDatabase &operator=(const FileDatabase &other) = delete;

    ~FileDatabase() override = default;

    void insert(const helloworld::UserData &data) override;

    const std::vector<std::unique_ptr<helloworld::UserData>>& select(const helloworld::UserData &query) override;

    void drop() override;

};

#endif //HELLOWORLD_SERVER_FILE_DATABASE_H_
