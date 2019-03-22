#include "client.h"

namespace helloworld {

Client::Client() : _transmission(std::make_unique<FileManager>(this, _username)) {
}

void Client::login(const std::string &username, const std::string &password) {}

void Client::logout() {
    _isConnected = false;
}

void Client::createAccount(const std::string &username,
                           const std::string &password) {}

void Client::deleteAccount() {}

std::vector<UserData> Client::getUsers(const std::string &query) { return {}; }

}  // namespace helloworld
