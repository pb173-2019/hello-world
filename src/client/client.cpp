#include "client.h"

namespace helloworld {

Client::Client() : _transmission(std::make_unique<ClientFiles>(this, _username)) {
}

void Client::login(const std::string &username, const std::string &password) {}

void Client::logout() {
}

void Client::createAccount(const std::string &username,
                           const std::string &password) {}

void Client::deleteAccount() {}

std::vector<UserData> Client::getUsers(const std::string &query) { return {}; }

}  // namespace helloworld
