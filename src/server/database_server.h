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
    virtual void insert(const UserData &data, bool autoIncrement) = 0;

    /**
     * Select from database data by query
     *
     * @param query search request
     * @return std::vector<std::unique_ptr<UserData>>& data matching the query
     */
    virtual const std::vector<std::unique_ptr<UserData>> &select(const UserData &query) = 0;

    /**
     * Select from database data by query
     *
     * @param query search request
     * @return std::vector<std::unique_ptr<UserData>>& data matching the query
     */
    virtual const std::vector<std::unique_ptr<UserData>> &selectLike(const UserData &query) = 0;

    /**
     * Delete user from database
     *
     * @param data must contain either user name or id
     * @return true if deletion succeeded
     */
    virtual bool remove(const UserData &data) = 0;

    /**
     * Delete the database tables
     */
    virtual void drop() = 0;

    /**
     * Delete table
     *
     * @param tablename table to delete
     */
    virtual void drop(const std::string &tablename) = 0;

    /**
   * Select data bundle from messages table
   * @param userId user id - to whom the data are sent to
   * @param blob data to store
   */
    virtual void insertData(uint32_t userId, const std::vector<unsigned char> &blob) = 0;

    /**
     * Destructively read *any* blob stored for the user with given id
     * @param userId userid to choose
     * @return any data blob with given user id, the database no longer holds this data
     */
    virtual std::vector<unsigned char> selectData(uint32_t userId) = 0;

    /**
     * Insert key bundle to into database
     * @param userId userId as primary key (bundle owner), must not be in table
     * @param blob key bundle in blob
     */
    virtual void insertBundle(uint32_t userId, const std::vector<unsigned char> &blob) = 0;

    /**
     * Select key bundle from database
     * @param userId user id as primary key (bundle owner)
     * @return copy of key bundle
     */
    virtual std::vector<unsigned char> selectBundle(uint32_t userId) = 0;

    /**
     * Update key bundle
     * @param userId userId as primary key
     * @param blob new bundle
     */
    virtual void updateBundle(uint32_t userId, const std::vector<unsigned char> &blob) = 0;

    /**
     * Delete key bundle from database
     * @param userId userid as primary key
     * @return true if succeeded
     */
    virtual bool removeBundle(uint32_t userId) = 0;

};

} //  namespace helloworld

#endif //HELLOWORLD_SERVER_DATABASE_H_
