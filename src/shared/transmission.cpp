#include "transmission.h"

namespace helloworld {

server_socket Network::server_callback = nullptr;
ServerTransmissionManager *Network::server_instance = nullptr;
std::map<std::string, std::pair<client_socket, UserTransmissionManager *>> Network::connection_callbacks{};

bool Network::enabled = false;

void Network::sendToServer() {
    if (!enabled)
        return;
    (server_instance->*server_callback)();
}

void Network::sendToUser(const std::string &username) {
    if (!enabled)
        return;
    auto found = connection_callbacks.find(username);
    if (found == connection_callbacks.end())
        throw Error("Invalid connection: not found.");
    (found->second.second->*found->second.first)();
}


} //namespace helloworld
