/**
 * @file sqlite_database.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Database file implementation
 * @version 0.1
 * @date 16. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_SQLITE_DATABASE_H_
#define HELLOWORLD_SERVER_SQLITE_DATABASE_H_

#include <cstdint>

#include "database.h"
#include "../shared/user_data.h"

#include "sqlite3.h"


class SQLite : Database {
    std::vector<std::unique_ptr<helloworld::UserData>> cache;
    std::string tablename{"users"};
    sqlite3 *handler = nullptr;

public:
    /**
     * Creates temporary in-memory database
     * with table named user
     */
    SQLite();

    /**
     * Creates file database wit table named user
     *
     * @param filename name of the database
     */
    explicit SQLite(std::string&& filename);

    // Copying is not available
    SQLite(const SQLite &other) = delete;

    SQLite &operator=(const SQLite &other) = delete;

    ~SQLite() override;

    void insert(const helloworld::UserData &data) override;

    const std::vector<std::unique_ptr<helloworld::UserData>>& select(const helloworld::UserData &query) override;

    void drop() override;

private:

    int execute(std::string&& command, int (*callback)(void*,int,char**,char**), void* fstArg);

    void createTableIfNExists();

    /**
     * Callback for execution, can perform, not used now
     * @param argc number of values in a row
     * @param argv values in array
     * @param colName coll names in array
     * @return 0 on success
     */
    static int fillData(void *data, int argc, char **argv, char **colName) {
        if (argc != 3)
            return 1;

        auto* cache = static_cast<std::vector<std::unique_ptr<helloworld::UserData>> *>(data);
        auto id = static_cast<uint32_t>(std::stol(argv[0]));
        helloworld::UserData temp{id, argv[1], argv[2]};
        cache->push_back(std::make_unique<helloworld::UserData>(temp));
        return 0;
    }

    static std::string getErrorMsgByReturnType(int ret);

};

#endif //HELLOWORLD_SERVER_SQLITE_DATABASE_H_
