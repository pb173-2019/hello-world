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

#include "../shared/user_data.h"
#include "database_server.h"

#include "sqlite3.h"

namespace helloworld {

const std::string specialCharacters = ":?\"%'";

class ServerSQLite : public ServerDatabase {
    std::vector<std::unique_ptr<UserData>> _cache;
    sqlite3 *_handler = nullptr;

   public:
    const std::vector<std::string> tables{"users", "bundles", "messages"};

    /**
     * Creates temporary in-memory database
     * with table named user
     */
    ServerSQLite();

    /**
     * Creates file database wit table named user
     *
     * @param filename name of the database, the filename string is modified
     *          filename without the '.db' file type specifier
     */
    explicit ServerSQLite(std::string &&filename);

    // Copying is not available
    ServerSQLite(const ServerSQLite &other) = delete;

    ServerSQLite &operator=(const ServerSQLite &other) = delete;

    ~ServerSQLite() override;

    /*
     * WORKING WITH USERDATA (table users)
     */
    uint32_t insert(const UserData &data, bool autoIncrement) override;
    UserData select(const UserData &query) const override;
    UserData select(uint32_t id) const override;
    UserData select(const std::string &username) const override;
    const std::vector<std::unique_ptr<UserData>> &selectLike(
        const UserData &query) override;
    const std::vector<std::unique_ptr<UserData>> &selectLike(
        const std::string &username) override;
    bool remove(const UserData &data) override;

    /*
     * WORKING WITH MESSAGES (table users)
     */
    void insertData(uint32_t userId,
                    const std::vector<unsigned char> &blob) override;
    std::vector<unsigned char> selectData(uint32_t userId) override;
    void deleteAllData(uint32_t userId) override;

    /*
     * WORKING WITH KEYBUNDLES (table users)
     */
    void insertBundle(uint32_t userId, const std::vector<unsigned char> &blob,
                      uint64_t timestamp = 0) override;
    std::vector<unsigned char> selectBundle(uint32_t userId) const override;
    uint64_t getBundleTimestamp(uint32_t userId) const override;
    void updateBundle(uint32_t userId,
                      const std::vector<unsigned char> &blob) override;
    void updateBundle(uint32_t userId, const std::vector<unsigned char> &blob,
                      uint64_t timestamp) override;
    bool removeBundle(uint32_t userId) override;

    void drop() override;

    void drop(const std::string &tablename) override;

   private:
    int _execute(std::string &&command,
                 int (*callback)(void *, int, char **, char **), void *fstArg);

    /**
     * Create all tables and their structures if n exists
     */
    void _createTablesIfNExists();

    /**
     * Callback for execution, perform selection - save data
     * @param argc number of values in a row
     * @param argv values in array
     * @param colName coll names in array
     * @return 0 on success
     */
    static int _fillData(void *data, int argc, char **argv,
                         char ** /*colName*/) {
        if (argc != 3) return 1;

        auto *cache =
            static_cast<std::vector<std::unique_ptr<UserData>> *>(data);
        auto id = static_cast<uint32_t>(std::stol(argv[0]));
        std::string pubkey(argv[2]);
        zero::bytes_t publicKey(pubkey.begin(), pubkey.end());
        UserData temp{id, argv[1], "", publicKey};
        cache->push_back(std::make_unique<UserData>(temp));
        return 0;
    }

    static std::string _getErrorMsgByReturnType(int ret);

    /**
     * Query check to protect from injection
     *
     * @param query query to check
     * @return query without special characters that would allowed to attack
     * database
     */
    static std::string _sCheck(std::string query);
};

}    //  namespace helloworld

#endif    // HELLOWORLD_SERVER_SQLITE_DATABASE_H_
