#include "sqlite_database.h"

#include <algorithm>

SQLite::SQLite() {
    if (int res = sqlite3_open(nullptr, &_handler) != SQLITE_OK) {
        throw std::runtime_error("Could not create database: " + _getErrorMsgByReturnType(res));
    }
    _createTableIfNExists();
}

SQLite::SQLite(std::string &&filename) {
    filename.push_back('\0');
    if (int res = sqlite3_open(nullptr, &_handler) != SQLITE_OK) {
        throw std::runtime_error("Could not create database. " + _getErrorMsgByReturnType(res));
    }
    _createTableIfNExists();
}

SQLite::~SQLite() {
    // todo: can return SQLITE_BUSY when not ready to release (backup) ... solve?
    if (sqlite3_close(_handler) != SQLITE_OK) {
        //todo cannot throw, but also cannot destruct...
    }
}

void SQLite::insert(const helloworld::UserData &data) {
    if (int res = _execute("INSERT INTO users VALUES (" +
                          std::to_string(data.id) + ", '" +
                          _sCheck(data.name) + "', '" +
                          data.publicKey + "');", nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Insert command failed: " + _getErrorMsgByReturnType(res));
    }
}

const std::vector<std::unique_ptr<helloworld::UserData>> &SQLite::select(const helloworld::UserData &query) {
    _cache.clear();
    int res;
    if (query.id == 0 && query.name.empty()) {
        res = _execute("SELECT * FROM users;", _fillData, &_cache);
    } else if (query.id == 0) {
        res = _execute("SELECT * FROM users WHERE username LIKE '%" + _sCheck(query.name) + "%' ORDER BY id DESC;",
                _fillData, &_cache);
    } else {
        res = _execute("SELECT * FROM users WHERE id=" + std::to_string(query.id) + ";", _fillData, &_cache);
    }
    if (res != SQLITE_OK)
        throw std::runtime_error("Select command failed: " + _getErrorMsgByReturnType(res));
    return _cache;
}

void SQLite::drop() {
    if (int res = _execute("DROP TABLE users;", nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Could not delete database: " + _getErrorMsgByReturnType(res));
    }
}

int SQLite::_execute(std::string &&command, int (*callback)(void *, int, char **, char **), void *fstArg) {
    command.push_back('\0'); //the c library - just to be sure
    char *error;
    int res = sqlite3_exec(_handler, command.data(), callback, fstArg, &error);
    if (res != SQLITE_OK) {
        printf("%s\n", error);
    }
    return res;
}

void SQLite::_createTableIfNExists() {
    if (int res = _execute("CREATE TABLE IF NOT EXISTS users ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                          "username TEXT, "
                          "pubkey TEXT);",
                          nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Could not create database: " + _getErrorMsgByReturnType(res));
    }
}

std::string SQLite::_sCheck(std::string query) {
    std::transform(query.begin(), query.end(), query.begin(), [](char c){
        return specialCharacters.find(c) == std::string::npos ? c : ' ';
    });
    return query;
}

std::string SQLite::_getErrorMsgByReturnType(int ret) {
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
