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

namespace helloworld {

class ServerDatabase {

public:
    ServerDatabase() = default;

    // Copying is not available
    ServerDatabase(const ServerDatabase &other) = delete;
    ServerDatabase &operator=(const ServerDatabase &other) = delete;
    virtual ~ServerDatabase() = default;

    /**
     * Insert into database data object
     *
     * @param data data to insert
     */
    virtual void insert(const UserData& data, bool autoIncrement) = 0;

    /**
     * Select from database data by query
     *
     * @param query search request
     * @return std::vector<std::unique_ptr<UserData>>& data matching the query
     */
    virtual const std::vector<std::unique_ptr<UserData>>& selectUsers(const UserData& query) = 0;

    /**
     * Select from database data by query
     *
     * @param query search request
     * @return std::vector<std::unique_ptr<UserData>>& data matching the query
     */
    virtual const std::vector<std::unique_ptr<UserData>>& selectUsersLike(const UserData& query) = 0;

    /**
     * Delete user from database
     *
     * @param data must contain either user name or id
     * @return true if deletion succeeded
     */
    virtual bool removeUser(const UserData& data) = 0;

    /**
     * Delete the database tables
     */
    virtual void drop() = 0;

    /**
     * Delete table
     *
     * @param tablename table to delete
     */
    virtual void drop(const std::string& tablename) = 0;

};

} //  namespace helloworld

#endif //HELLOWORLD_SERVER_DATABASE_H_
