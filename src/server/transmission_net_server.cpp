#include "transmission_net_server.h"

#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

#include "../shared/base_64.h"
#include "../shared/transmission.h"
#include "../shared/utils.h"

#include <QThread>
#include <QtCore>
#include <QtNetwork>

namespace helloworld {

ServerSocket::ServerSocket(QTcpSocket *socket, std::string username,
                           ServerTCP *server, QObject *parent)
    : QObject(parent),
      server(server),
      socket(socket),
      username(std::move(username)) {
    socket->setParent(this);
    connect(socket, &QTcpSocket::readyRead, this, &ServerSocket::receive,
            Qt::QueuedConnection);
    connect(socket, &QTcpSocket::stateChanged, this,
            &ServerSocket::updateConnection, Qt::QueuedConnection);
}

ServerSocket::ServerSocket(ServerSocket &&other) {
    server = std::move(other.server);
    username = std::move(other.username);
    socket = std::move(other.socket);
    socket->setParent(this);
    other._owned = false;
}

ServerSocket &ServerSocket::operator=(ServerSocket &&other) {
    server = std::move(other.server);
    username = std::move(other.username);
    socket = std::move(other.socket);
    socket->setParent(this);
    other._owned = false;
    return *this;
}

void ServerSocket::receive() { server->_receive(socket, username); }

void ServerSocket::updateConnection(QAbstractSocket::SocketState state) {
    switch (state) {
        case QAbstractSocket::SocketState::UnconnectedState: {
            emit disconnected(socket);
            break;
        }
        default:
            break;
    }
}

void ServerSocket::send(QByteArray data) {
    socket->write(data.data(), data.size());
}

void ServerSocket::closeConnection() { socket->disconnectFromHost(); }

/*************************************************************************************/

SocketManager::SocketManager(ServerTCP *server, QObject *parent)
    : QObject(parent), server(server), thread(new EventThread()) {
    this->moveToThread(thread);
    thread->start();
}

void SocketManager::emplace(QTcpSocket *socket, const std::string &name) {
    lock.lockForWrite();
    socket->moveToThread(thread);
    ownedSockets.emplace_back(new ServerSocket(socket, name, server, this));
    connect(ownedSockets.back(), &ServerSocket::disconnected, this,
            &SocketManager::remove);
    lock.unlock();
}

bool SocketManager::remove(const QTcpSocket *socket) {
    auto it = std::find_if(
        ownedSockets.begin(), ownedSockets.end(),
        [&socket](const ServerSocket *o) { return o->socket == socket; });
    if (it != ownedSockets.end()) {
        QWriteLocker lock1(&lock);
        auto name = QString::fromStdString((*it)->username);
        ownedSockets.erase(it);
        emit removed(std::move(name));
        return true;
    }
    return false;
}

void SocketManager::toRegister(QTcpSocket *socket, const QString &name) {
    emplace(socket, name.toStdString());
}

/*****************************************************************************/

QThreadStorage<PtrWrap<QTcpSocket>> ServerTCP::_lastSending;

void ServerTCP::cleanAfter(QString name) {
    emit clossedConnection(std::move(name));
}

SocketManager *ServerTCP::minThread() {
    QReadLocker l(&lock);
    auto min = _threads.begin();
    auto _end = _threads.end();
    for (auto i = min; i != _end; ++i) {
        if ((*i)->ownedSockets.size() < (*min)->ownedSockets.size()) {
            min = i;
        }
    }
    return min->get();
}

void ServerTCP::discoverConnection() {
    QTcpSocket *lastIncomming = _server.nextPendingConnection();
    _lastSending.setLocalData(lastIncomming);
    connect(lastIncomming, SIGNAL(readyRead()), this, SLOT(receive()));
    connect(lastIncomming, &QAbstractSocket::stateChanged, this,
            &ServerTCP::updateConnection);
    emit conn(lastIncomming->peerAddress(), lastIncomming->peerPort());
}

void ServerTCP::updateConnection(QAbstractSocket::SocketState state) {
    switch (state) {
        case QAbstractSocket::SocketState::UnconnectedState: {
            QTcpSocket *sender = static_cast<QTcpSocket *>(QObject::sender());
            sender->deleteLater();
            break;
        }
        default:
            break;
    }
}

void ServerTCP::_receive(QTcpSocket *sender, const std::string &name) {
    _lastSending.setLocalData(sender);
    QByteArray data = sender->readAll();
    std::stringstream received{};
    received.write(data.data(), data.size());
    std::string msg;
    while (std::getline(received, msg, '\0')) {
        std::stringstream result{}, from(msg);
        _base64.toStream(from, result);

        Callable<void, bool, const std::string &, std::stringstream &&>::call(
            callback, !name.empty(), name, std::move(result));
    }
}

void ServerTCP::receive() {
    QTcpSocket *sender = dynamic_cast<QTcpSocket *>(QObject::sender());
    _receive(sender);
}

ServerTCP::ServerTCP(
    Callable<void, bool, const std::string &, std::stringstream &&> *callback,
    QObject *parent)
    : QObject(parent), ServerTransmissionManager(callback) {
    // start threads
    int optimal = QThread::idealThreadCount() - 1;
    assert(optimal > 0);
    _threads.reserve(static_cast<size_t>(optimal));
    for (int i = 0; i < optimal; ++i) {
        _threads.push_back(std::make_unique<SocketManager>(this));
        connect(_threads.back().get(), &SocketManager::removed, this,
                &ServerTCP::cleanAfter);
    }

    // start listenning
    _server.listen(QHostAddress::Any, 5000);
    if (!_server.isListening())
        throw std::runtime_error("Couldn't start a server");
    connect(&_server, SIGNAL(newConnection()), this,
            SLOT(discoverConnection()));
}

void ServerTCP::_send(QTcpSocket *receiver, QByteArray &data) {
    receiver->write(data.data(), data.size());
}

void ServerTCP::send(const std::string &usrname, std::iostream &data) {
    data.seekg(0, std::ios::beg);
    std::stringstream toSend;
    _base64.fromStream(data, toSend);
    toSend << '\0';
    QByteArray arr(toSend.str().data(), getSize(toSend));
    QTcpSocket *client = nullptr;
    if (!usrname.empty()) {
        // TODO: use cv
        while (!client) client = getSocket(usrname);

        auto p = dynamic_cast<ServerSocket *>(client->parent());
        connect(this, &ServerTCP::forward, p, &ServerSocket::send);
        emit forward(arr);
        disconnect(this, &ServerTCP::forward, p, &ServerSocket::send);
        return;
    }
    client = _lastSending.localData();

    _send(client, arr);
}

void ServerTCP::registerConnection(const std::string &username) {
    QTcpSocket *sender = _lastSending.localData();
    _lastSending.setLocalData({});
    if (auto owner =
            dynamic_cast<ServerSocket *>(sender->parent()) != nullptr) {
        return;
    }
    if (username.empty()) return;
    disconnect(sender, SIGNAL(readyRead()), this, SLOT(receive()));
    disconnect(sender, &QAbstractSocket::stateChanged, this,
               &ServerTCP::updateConnection);

    auto connectionManager = minThread();

    sender->setParent(nullptr);
    sender->moveToThread(connectionManager->thread);

    connect(this, &ServerTCP::toRegister, connectionManager,
            &SocketManager::toRegister);
    emit toRegister(sender, QString().fromStdString(username));
    disconnect(this, &ServerTCP::toRegister, connectionManager,
               &SocketManager::toRegister);
}

void ServerTCP::discardNewConnection(const std::vector<unsigned char> &data) {
    QTcpSocket *sender = static_cast<QTcpSocket *>(QObject::sender());
    assert(sender);
    emit disconn(sender->peerAddress(), sender->peerPort());
    sender->write(reinterpret_cast<const char *>(data.data()),
                  static_cast<long long>(data.size()));

    disconnect(sender, SIGNAL(readyRead()), this, SLOT(recieve()));
    sender->deleteLater();
}

bool ServerTCP::removeConnection(const std::string &username) {
    auto socket = getSocket(username);
    if (!socket) return false;

    auto socketWrapper = dynamic_cast<ServerSocket *>(socket->parent());
    if (!socketWrapper) return false;

    connect(this, &ServerTCP::toClose, socketWrapper,
            &ServerSocket::closeConnection);
    emit toClose();
    disconnect(this, &ServerTCP::toClose, socketWrapper,
               &ServerSocket::closeConnection);
    return true;
}

bool ServerTCP::exists(const std::string &username) {
    return getSocket(username) != nullptr;
}

// todo will return even auth-waiting users ! consider the consequence
std::set<std::string> ServerTCP::getOpenConnections() {
    lock.lockForRead();
    std::set<std::string> names;
    for (auto &thread : _threads) {
        thread->lock.lockForRead();
        for (const auto &connection : thread->ownedSockets) {
            names.insert(connection->username);
        }
        thread->lock.unlock();
    }
    lock.unlock();
    return names;
}

QTcpSocket *ServerTCP::getSocket(const std::string &username) {
    QReadLocker lock1(&lock);
    for (auto &thread : _threads) {
        QReadLocker lock2(&thread->lock);
        for (const auto &connection : thread->ownedSockets)
            if (username == connection->username) {
                return connection->socket;
            }
    }
    return nullptr;
}

std::string ServerTCP::getName(const QTcpSocket *client) {
    QReadLocker lock1(&lock);
    for (auto &thread : _threads) {
        QReadLocker lock2(&thread->lock);
        for (const auto &connection : thread->ownedSockets)
            if (client == connection->socket) {
                return connection->username;
            }
    }
    return "";
}

}    // namespace helloworld
