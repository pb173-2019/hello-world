#include "connection.h"

namespace helloworld {

Connection::Connection(const std::string& address) {}

Connection::~Connection() {}

Response Connection::sendRequest(Request request) { return {}; }

SecureChannel Connection::openSecureChannel(long id) {
  return SecureChannel(0);
}

void Connection::closeSecureChannel(long id) {}

void Connection::sendMessage(const std::string& message, long id) {}

}  // namespace helloworld
