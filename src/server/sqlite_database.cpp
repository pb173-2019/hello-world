#include "sqlite_database.h"

#include <algorithm>

#include "../shared/serializable_error.h"

namespace helloworld {

    ServerSQLite::ServerSQLite() {
        if (int res = sqlite3_open(nullptr, &_handler) != SQLITE_OK) {
            throw Error("Could not create database: " + _getErrorMsgByReturnType(res));
        }
        _createTablesIfNExists();
    }

    ServerSQLite::ServerSQLite(std::string &&filename) {
        filename.push_back('\0');
        if (int res = sqlite3_open(filename.c_str(), &_handler) != SQLITE_OK) {
            throw Error("Could not create database. " + _getErrorMsgByReturnType(res));
        }
        _createTablesIfNExists();
    }

    ServerSQLite::~ServerSQLite() {
        // todo: can return SQLITE_BUSY when not ready to release (backup) ... solve?
        if (sqlite3_close(_handler) != SQLITE_OK) {
            //todo cannot throw, but also cannot destruct...
        }
    }

    uint32_t ServerSQLite::insert(const UserData &data, bool autoIncrement) {
        std::string query = "INSERT INTO users ";
        if (autoIncrement) {
            query += "(username, pubkey) VALUES ('";
        } else {
            query += "VALUES (" + std::to_string(data.id) + ", '";
        }
        query += _sCheck(data.name) + "', '" +
                 std::string(data.publicKey.begin(), data.publicKey.end()) + "');";

        if (int res = _execute(std::move(query), nullptr, nullptr) != SQLITE_OK) {
            throw Error("Insert command failed: " + _getErrorMsgByReturnType(res));
        }
        uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(_handler));
        return id;
    }
    const std::vector<std::unique_ptr<UserData>> &ServerSQLite::selectLike(const UserData &query) {
        _cache.clear();
        int res = _execute("SELECT * FROM users WHERE username LIKE '%" + _sCheck(query.name) + "%' ORDER BY id DESC;",
                           _fillData, &_cache);
        if (res != SQLITE_OK)
            throw Error("Select command failed: " + _getErrorMsgByReturnType(res));
        return _cache;
    }

    const std::vector<std::unique_ptr<UserData>> &ServerSQLite::select(const UserData &query) {
        _cache.clear();
        int res;
        if (query.id == 0 && query.name.empty()) {
            res = _execute("SELECT * FROM users;", _fillData, &_cache);
        } else if (query.id == 0) {
            res = _execute("SELECT * FROM users WHERE username='" + _sCheck(query.name) + "' ORDER BY id DESC;",
                           _fillData, &_cache);
        } else {
            res = _execute("SELECT * FROM users WHERE id=" + std::to_string(query.id) + ";", _fillData, &_cache);
        }
        if (res != SQLITE_OK)
            throw Error("Select command failed: " + _getErrorMsgByReturnType(res));
        return _cache;
    }

    bool ServerSQLite::remove(const UserData &data) {
        if (data.id == 0)
            return _execute("DELETE FROM users WHERE username "
                            "= '" + _sCheck(data.name) + "';", nullptr, nullptr) == SQLITE_OK;
        return _execute("DELETE FROM users WHERE id = " + std::to_string(data.id) +
                        ";", nullptr, nullptr) == SQLITE_OK;
    }

    void ServerSQLite::insertData(uint32_t userId, const std::vector<unsigned char>& blob) {
        sqlite3_stmt *statement = nullptr;
        std::string query = "INSERT INTO messages (userid, data) VALUES (?, ?)";
        sqlite3_prepare_v2(_handler, query.c_str(), -1, &statement, nullptr);
        sqlite3_bind_int(statement, 1, userId);
        sqlite3_bind_blob64(statement, 2, blob.data(), blob.size() * sizeof(unsigned char), SQLITE_STATIC);
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw Error("Failed to store blob into table 'messages'.");
        sqlite3_finalize(statement);
    }

    std::vector<unsigned char> ServerSQLite::selectData(uint32_t userId) {
        sqlite3_stmt *statement = nullptr;
        std::string query = "SELECT id, data FROM messages WHERE userid = ?";
        sqlite3_prepare_v2(_handler, query.c_str(), -1, &statement, nullptr);
        sqlite3_bind_int(statement, 1, userId);

        std::vector<unsigned char> blob;
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const auto *ptr = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(statement, 1));
            blob.resize(static_cast<unsigned long>(
                                sqlite3_column_bytes(statement, 1) / static_cast<int>(sizeof(unsigned char))));
            std::copy(ptr, ptr + blob.size(), blob.data());

            auto id = static_cast<uint32_t>(sqlite3_column_int64(statement, 0));
            if (_execute("DELETE FROM messages WHERE id = " + std::to_string(id) + ";",
                    nullptr, nullptr) != SQLITE_OK) {
                throw Error("Failed to delete message when selecting.");
            }
        }
        sqlite3_finalize(statement);
        return blob;
    }


    void ServerSQLite::insertBundle(uint32_t userId, const std::vector<unsigned char>& blob) {
        sqlite3_stmt *statement = nullptr;
        std::string query = "INSERT INTO bundles VALUES (?, ?)";
        sqlite3_prepare_v2(_handler, query.c_str(), -1, &statement, nullptr);
        sqlite3_bind_int(statement, 1, userId);
        sqlite3_bind_blob64(statement, 2, blob.data(), blob.size() * sizeof(unsigned char), SQLITE_STATIC);
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw Error("Failed to store blob into table 'bundles'.");
        sqlite3_finalize(statement);
    }

    std::vector<unsigned char> ServerSQLite::selectBundle(uint32_t userId) {
        sqlite3_stmt *statement = nullptr;
        std::string query = "SELECT data FROM bundles WHERE userid = ?";
        sqlite3_prepare_v2(_handler, query.c_str(), -1, &statement, nullptr);
        sqlite3_bind_int(statement, 1, userId);

        std::vector<unsigned char> blob;
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const auto *ptr = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(statement, 0));
            blob.resize(static_cast<unsigned long>(
                                sqlite3_column_bytes(statement, 0) / static_cast<int>(sizeof(unsigned char))));
            std::copy(ptr, ptr + blob.size(), blob.data());
        }
        sqlite3_finalize(statement);
        return blob;
    }

    void ServerSQLite::updateBundle(uint32_t userId, const std::vector<unsigned char>& blob) {
        sqlite3_stmt *statement = nullptr;
        std::string query = "UPDATE bundles SET data = ? WHERE userid = ?";
        sqlite3_prepare_v2(_handler, query.c_str(), -1, &statement, nullptr);
        sqlite3_bind_int(statement, 2, userId);
        sqlite3_bind_blob64(statement, 1, blob.data(), blob.size() * sizeof(unsigned char), SQLITE_STATIC);
        if (sqlite3_step(statement) != SQLITE_DONE)
            throw Error("Failed to store blob into table 'bundles'.");
        sqlite3_finalize(statement);
    }

    /**
     * Delete key bundle from database
     * @param userId userid as primary key
     * @return true if succeeded
     */
    bool ServerSQLite::removeBundle(uint32_t userId) {
        return _execute("DELETE FROM bundles WHERE userid = " + std::to_string(userId) + ";",
                        nullptr, nullptr) == SQLITE_OK;
    }

    void ServerSQLite::drop(const std::string &tablename) {
        if (int res = _execute("DROP TABLE " + tablename + ";", nullptr, nullptr) != SQLITE_OK) {
            throw Error("Could not delete database: " + _getErrorMsgByReturnType(res));
        }
    }

    void ServerSQLite::drop() {
        for (const auto &table : tables) {
            drop(table);
        }
    }

    int ServerSQLite::_execute(std::string &&command, int (*callback)(void *, int, char **, char **), void *fstArg) {
        command.push_back('\0'); //the c library - just to be sure
        char *error;
        int res = sqlite3_exec(_handler, command.data(), callback, fstArg, &error);
        if (res != SQLITE_OK) {
            printf("%s\n", error);
        }
        return res;
    }

    void ServerSQLite::_createTablesIfNExists() {
        if (int res = _execute("CREATE TABLE IF NOT EXISTS users ("
                               "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                               "username TEXT, "
                               "pubkey TEXT);",
                               nullptr, nullptr) != SQLITE_OK) {
            throw Error("Could not create users database: " + _getErrorMsgByReturnType(res));
        }
        // skip id 0 reserved for special use
        _execute("UPDATE SQLITE_SEQUENCE SET seq = 0 WHERE name = 'users';", nullptr, nullptr);

        if (int res = _execute("CREATE TABLE IF NOT EXISTS messages ("
                               "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                               "userid INTEGER, "
                               "data BLOB);",
                               nullptr, nullptr) != SQLITE_OK) {
            throw Error("Could not create data database: " + _getErrorMsgByReturnType(res));
        }

        if (int res = _execute("CREATE TABLE IF NOT EXISTS bundles ("
                               "userid INTEGER PRIMARY KEY, "
                               "data BLOB);",
                               nullptr, nullptr) != SQLITE_OK) {
            throw Error("Could not create key bundles database: " + _getErrorMsgByReturnType(res));
        }
    }


    std::string ServerSQLite::_sCheck(std::string query) {
        std::transform(query.begin(), query.end(), query.begin(), [](char c) {
            return specialCharacters.find(c) == std::string::npos ? c : ' ';
        });
        return query;
    }

    std::string ServerSQLite::_getErrorMsgByReturnType(int ret) {
        switch (ret) {
            /*
             * Doesn't consider following:
             * SQLITE_LOCKED, SQLITE_BUSY, SQLITE_NOTFOUND, SQLITE_PROTOCOL, SQLITE_EMPTY,
             * SQLITE_SCHEMA, SQLITE_CONSTRAINT, SQLITE_MISUSE, SQLITE_NOLFS, SQLITE_AUTH,
             * SQLITE_FORMAT, SQLITE_RANGE, SQLITE_NOTICE, SQLITE_DONE, SQLITE_ROW
             */
            case SQLITE_ERROR :
                return "Generic error.";
            case SQLITE_INTERNAL :
                return "Internal logical error.";
            case SQLITE_PERM :
                return "Access permision denied.";
            case SQLITE_ABORT :
                return "Process aborted.";
            case SQLITE_NOMEM :
                return "Failed to allocate memory.";
            case SQLITE_READONLY :
                return "Database is read only.";
            case SQLITE_INTERRUPT :
                return "Operation interrupted.";
            case SQLITE_IOERR :
                return "IO operation failed.";
            case SQLITE_CORRUPT :
                return "Database file is corrupted.";
            case SQLITE_FULL :
                return "Insertion failed: database full.";
            case SQLITE_CANTOPEN :
                return "Filed to open database file.";
            case SQLITE_TOOBIG :
                return "Inserted data exceeds limit.";
            case SQLITE_MISMATCH :
                return "Data type mismatch.";
            case SQLITE_NOTADB :
                return "File supplied in not a database file.";
            case SQLITE_WARNING :
                return "Warnings from sqlite3_log().";
            default:
                return "Unknown error.";
        }
    }

} //  namespace helloworld
