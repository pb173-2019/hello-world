/**
 * @file config.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief
 * @version 0.1
 * @date 3. 4. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_CLIENT_CONFIG_H_
#define HELLOWORLD_CLIENT_CONFIG_H_

#include <string>

const std::string idRSApriv{"_priv.pem"};
const std::string idRSApub{"_pub.pem"};

const std::string serverPriv{"server_priv.pem"};
const std::string serverPub{"server_pub.pem"};

const std::string idC25519priv{"_identity.key"};
const std::string idC25519pub{"_identity.pub"};
const std::string preC25519priv{"_prekey.key"};
const std::string preC25519pub{"_prekey.pub"};
const std::string oneTimeC25519priv{"_onetime.key"};
const std::string oneTimeC25519pub{"_onetime.pub"};

#endif //HELLOWORLD_CLIENT_CONFIG_H_
