/**
 * @file database.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Database interface
 * @version 0.1
 * @date 16. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SERVER_DATABASE_H_
#define HELLOWORLD_SERVER_DATABASE_H_

#include <memory>

#include "../shared/user_data.h"

class Database {

public:
    Database() = default;
    // Copying is not available
    Database(const Database &other) = delete;
    Database &operator=(const Database &other) = delete;
    virtual ~Database() = default;

    /**
     * Insert into database data object
     *
     * @param data data to insert
     */
    virtual void insert(const helloworld::UserData& data) = 0;

    /**
     * Select from database data by query
     *
     * @param query search request
     * @return std::vector<std::unique_ptr<helloworld::UserData>>& data matching the query
     */
    virtual const std::vector<std::unique_ptr<helloworld::UserData>>& select(const helloworld::UserData& query) = 0;

    /**
     * Delete the database
     */
    virtual void drop() = 0;

};

#endif //HELLOWORLD_SERVER_DATABASE_H_
