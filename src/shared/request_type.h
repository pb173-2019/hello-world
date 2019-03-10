/**
 * @file request_type.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief Request type enum
 * @version 0.1
 * @date 2019-03-09
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_REQUESTTYPE_H_
#define HELLOWORLD_SHARED_REQUESTTYPE_H_

namespace helloworld {

enum class RequestType { LOGIN, LOGOUT, CREATE, DELETE, SEND, RECEIVE, FIND };

}  // namespace helloworld

#endif  // HELLOWORLD_SHARED_REQUESTTYPE_H_
