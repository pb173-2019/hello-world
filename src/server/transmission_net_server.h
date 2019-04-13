/**
 * @file transmission_net_server.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager implementation
 *          temporary testing solution
 *
 * @version 0.1
 * @date 21. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
#define HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_

#include <fstream>
#include <sstream>
#include <set>
#include <cstring>

#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"

#include <QtCore>
#include <QtNetwork>

namespace helloworld {

class ServerSocket : public QObject {
Q_OBJECT

    bool _owned = true;

public:
    QTcpSocket *socket;
    std::string username;

    explicit ServerSocket(QTcpSocket *socket, std::string username, QObject *parent = nullptr) :
            QObject(parent), socket(socket), username(std::move(username)) {
    }

    // Copying is not available
    ServerSocket(const ServerSocket &other) = delete;

    ServerSocket &operator=(const ServerSocket &other) = delete;

    ServerSocket(ServerSocket &&other) {
        socket = other.socket;
        other._owned = false;
    }

    ServerSocket &operator=(ServerSocket &&other) {
        socket->~QTcpSocket();
        socket = other.socket;
        other._owned = false;
        return *this;
    }

    ~ServerSocket() override {
        if (_owned) socket->~QTcpSocket();
    }
};


class ServerTCP : public QObject, public ServerTransmissionManager {
Q_OBJECT

    Base64 _base64;
    std::vector<ServerSocket> _connections;

    QTcpServer _server;
    QTcpSocket *_lastIncomming;

public slots:

    /**
     * Called on new incomming connection
     */
    void discoverConnection() {
        _lastIncomming = _server.nextPendingConnection();
    }

    void updateConnection(QAbstractSocket::SocketState state) {
        switch (state) {
            case QAbstractSocket::SocketState::UnconnectedState: {
                QTcpSocket *sender = static_cast<QTcpSocket *>(QObject::sender());
                removeConnection(sender);
                break;
            }
            default:
                break;
        }
    }

    void receive() override {
        //todo ugly, ugly
        QTcpSocket *sender = static_cast<QTcpSocket *>(QObject::sender());
        QByteArray data = sender->readAll();

        std::stringstream received{};
        received.write(data.data(), data.size());

        std::stringstream result{};
        _base64.toStream(received, result);

        const std::string &name = getName(sender);
        //todo invalid, name might be empty, the server CANNOT count on name being valid value
        Callable<void, bool, const std::string &, std::stringstream &&>::call(callback, name.empty(),
                                                                              name, std::move(result));
    }

public:
    explicit ServerTCP(Callable<void, bool, const std::string &, std::stringstream &&> *callback,
                       QObject *parent = nullptr) : QObject(parent),
            ServerTransmissionManager(callback) {

        _server.listen(QHostAddress::Any, 5000);
        connect(&_server, SIGNAL(newConnection()), this, SLOT(discoverConnection()));
    };

    // Copying is not available
    ServerTCP(const ServerTCP &other) = delete;

    ServerTCP &operator=(const ServerTCP &other) = delete;

    ~ServerTCP() override = default;

    void send(const std::string &usrname, std::iostream &data) override {
        data.seekg(0, std::ios::beg);
        std::stringstream toSend;
        _base64.fromStream(data, toSend);

        QTcpSocket *client = getSocket(usrname);
        //todo ugly, ugly, ugly
        size_t length = getSize(toSend);
        std::vector<char> bytes(length);
        toSend.read(bytes.data(), length);

        client->write(bytes.data(), bytes.size());
    }

    /**
     * Mark some connection as opened
     * @param connection
     */
    void registerConnection(const std::string &username) override {
        if (username.empty())
            return;

        connect(_lastIncomming, SIGNAL(readyRead()), this, SLOT(receive()));
        connect(_lastIncomming, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this,
                SLOT(updateConnection(QAbstractSocket::SocketState)));
        _connections.emplace_back(_lastIncomming, username);
        _lastIncomming = nullptr;
    }

    /**
     * Called when new connection fails -> server sends generic error and calls destructor
     * @param data data to send before discarding the connectino
     */
    void discardNewConnection(const std::vector<unsigned char> &data) override {
        _lastIncomming->write(reinterpret_cast<const char *>(data.data()), data.size());
        _lastIncomming->~QTcpSocket();
        _lastIncomming = nullptr;
    }

    /**
     * Release connection
     * @param connection7
     * @return true if connection deleted
     */
    bool removeConnection(const std::string &username) override {
        for (auto i = _connections.begin(); i < _connections.end(); i++) {
            if (i->username == username) {
                _connections.erase(i);
                return true;
            }
        }
        return false;
    }

    /**
     * Check filename for its connection
     * @param filename name to check
     * @return 0 if no connection found, otherwise >0
     */
    bool exists(const std::string &username) {
        return getSocket(username) != nullptr;
    }

    /**
     * Get names of all connected users
     * @return
     */
    //todo will return even auth-waiting users ! consider the consequence
    std::set<std::string> getOpenConnections() override {
        std::set<std::string> names;
        for (const auto &con : _connections) {
            names.emplace(con.username);
        }
        return names;
    }

private:
    //todo maybe use hashmap or treemap - better than O(n)
    QTcpSocket *getSocket(const std::string &username) {
        for (const auto &con : _connections) {
            if (con.username == username)
                return con.socket;
        }
        return nullptr;
    }

    std::string getName(const QTcpSocket *client) {
        for (const auto &con : _connections) {
            if (con.socket == client)
                return con.username;
        }
        return "";
    }

    void removeConnection(const QTcpSocket *client) {
        for (auto i = _connections.begin(); i < _connections.end(); i++) {
            if (i->socket == client) {
                _connections.erase(i);
                return;
            }
        }
    }
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
