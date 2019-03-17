#include "sqlite_database.h"

SQLite::SQLite() {
    if (sqlite3_open(nullptr, &handler) != SQLITE_OK) {
        throw std::runtime_error("Could not create database.");
    }
    createTableIfNExists();
}

SQLite::SQLite(std::string &&filename) {
    filename.push_back('\0');
    if (sqlite3_open(nullptr, &handler) != SQLITE_OK) {
        throw std::runtime_error("Could not create database.");
    }
    tablename = "users";
    createTableIfNExists();
}

SQLite::~SQLite() {
    // todo: can return SQLITE_BUSY when not ready to release (backup) ... solve?
    if (sqlite3_close(handler) != SQLITE_OK) {
        //todo cannot throw, but also cannot destruct...
    }
}

void SQLite::insert(const helloworld::UserData &data) {
    execute("INSERT INTO users VALUES (" +
            std::to_string(data.id) + ", '" +
            data.name + "', '" +
            data.publicKey + "');", nullptr, nullptr);
}

const std::vector<std::unique_ptr<helloworld::UserData>> &SQLite::select(const helloworld::UserData &query) {
    cache.clear();
    if (query.id == 0 && query.name.empty()) {
        execute("SELECT * FROM users;", fillData, &cache);
    } else if (query.id == 0) {
        execute("SELECT * FROM users WHERE username LIKE '%" + query.name + "%' ORDER BY id DESC;", fillData, &cache);
    } else {
        execute("SELECT * FROM users WHERE id=" + std::to_string(query.id) + ";", fillData, &cache);
    }
    return cache;
}

void SQLite::drop() {
    execute("DROP TABLE users;", nullptr, nullptr);
}

void SQLite::execute(std::string &&command, int (*callback)(void *, int, char **, char **), void *fstArg) {
    command.push_back('\0'); //the c library - just to be sure
    char *error;
    if (sqlite3_exec(handler, command.data(), callback, fstArg, &error) != SQLITE_OK) {
        printf("%s\n", error);
        throw std::runtime_error("could not complete the database execution.");
    }
}

void SQLite::createTableIfNExists() {
    execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, pubkey TEXT);",
            nullptr, nullptr);
}