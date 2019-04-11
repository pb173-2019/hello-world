#include "transmission.h"

namespace helloworld {


server_socket Network::server_callback = nullptr;
ServerTransmissionManager *Network::server_instance = nullptr;
std::map<std::string, std::pair<client_socket, UserTransmissionManager *>> Network::connection_callbacks{};
std::vector<std::pair<std::string, std::vector<unsigned char>>> Network::delayed{};

bool Network::enabled = false;
bool Network::problem = false;

void Network::release() {
    if (delayed.empty())
        return;
    std::pair<std::string, std::vector<unsigned char>> &delayedTcp = *(delayed.end() - 1);
    std::ofstream message{delayedTcp.first, std::ios::out | std::ios::binary};
    if (!message)
        throw Error("Failed to send delayed message.");

    write_n(message, delayedTcp.second);
    delayed.pop_back();
    message.close();

    (server_instance->*server_callback)();
}

void Network::discard() {
    delayed.pop_back();
}

void Network::sendToServer() {
    if (!enabled)
        return;

    if (problem) {
        std::string tcp = getFile(".tcp");
        std::ifstream message{tcp, std::ios::in | std::ios::binary};
        if (!message)
            return;
        size_t length = getSize(message);
        std::vector<unsigned char> data(length);
        read_n(message, data.data(), data.size());
        delayed.emplace_back(tcp, data);
        message.close();
    } else {
        (server_instance->*server_callback)();
    }
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
