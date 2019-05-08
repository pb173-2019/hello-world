#include "transmission_net_client.h"
#include <QDataStream>
#include <QObject>
#include <QtNetwork>
#include <cstdint>
#include <memory>
#include <sstream>
#include "../shared/base_64.h"
#include "../shared/transmission.h"
#include "../shared/utils.h"

namespace helloworld {

ClientSocket::ClientSocket(Callable<void, std::stringstream &&> *callback,
                           std::string username, const std::string &addr,
                           uint16_t port, QObject *parent)
    : QObject(parent),
      UserTransmissionManager(callback, std::move(username),
                              UserTransmissionManager::Status::NEED_INIT),
      _port(port),
      _address(QString().fromStdString(addr)),
      _socket(new QTcpSocket(this)) {
    QObject::connect(_socket.get(),
                     SIGNAL(stateChanged(QAbstractSocket::SocketState)), this,
                     SLOT(_state_change(QAbstractSocket::SocketState)));
    connect(_socket.get(), SIGNAL(error(QAbstractSocket::SocketError)), this,
            SLOT(onError(QAbstractSocket::SocketError)));
    connect(_socket.get(), SIGNAL(readyRead()), this, SLOT(receive()));
}

void ClientSocket::setHostAddress(const std::string &address) {
    _address = _address.fromStdString(address);
}

void ClientSocket::setHostPort(uint16_t port) { _port = port; }

void ClientSocket::send(std::iostream &data) {
    std::stringstream inBase;
    _base64.fromStream(data, inBase);
    inBase << '\0';    // to distinguish messages
    if (!wait_connected()) {
        return;
    }
    QByteArray qdata(inBase.str().data(),
                     static_cast<int>(inBase.str().size()));
    _socket->write(qdata);
    _socket->flush();
    emit sent();
}

void ClientSocket::closeConnection() {
    _status = NEED_INIT;
    _socket->disconnectFromHost();
    emit disconnected();
}

void ClientSocket::onError(QAbstractSocket::SocketError /*socketError*/) {
    emit disconnected();
}

void ClientSocket::receive() {
    QByteArray data = _socket->readAll();
    std::stringstream ss(data.toStdString());
    std::string line;
    while (!std::getline(ss, line, '\0').eof()) {
        std::stringstream inBase(line), fromBase{};
        _base64.toStream(inBase, fromBase);
        callback->callback(std::move(fromBase));
    }
    emit received();
}

void ClientSocket::init() {
    _socket->connectToHost(_address, static_cast<quint16>(_port));
    if (wait_connected()) {
        _status = OK;
    }
}

void ClientSocket::_state_change(QAbstractSocket::SocketState state) {
    if (_status != NEED_INIT &&
        (state == QAbstractSocket::SocketState::UnconnectedState ||
         state == QAbstractSocket::SocketState::ClosingState)) {
        _status = NEED_INIT;
        emit disconnected();
    }
}

bool ClientSocket::wait_connected() {
    while (_socket->state() == QAbstractSocket::SocketState::ConnectingState &&
           !_socket->waitForConnected())
        ;

    if (_socket->state() != QAbstractSocket::SocketState::ConnectedState) {
        if (_status != NEED_INIT) {
            _status = NEED_INIT;
            emit disconnected();
        }
        return false;
    }
    return true;
}

}    // namespace helloworld