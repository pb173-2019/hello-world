//
// Created by ivan on 9.4.19.
//

#ifndef HELLOWORLD_TRANSMISSION_NET_CLIENT_H
#define HELLOWORLD_TRANSMISSION_NET_CLIENT_H

#include <sstream>
#include <QObject>
#include <QtNetwork>
#include <cstdint>
#include <memory>
#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"

namespace helloworld {

class ClientSocket : public QObject, public UserTransmissionManager {
    Q_OBJECT
    Base64 _base64;

    qint16 _port{};
    QString _address{};

    std::unique_ptr<QTcpSocket> _socket;
public:
    explicit ClientSocket(Callable<void, std::stringstream &&> *callback,
                        std::string username,
                        const std::string& addr = "",
                         uint16_t port = 500, QObject *parent = nullptr)
                         : QObject(parent)
                         , UserTransmissionManager(callback, std::move(username), UserTransmissionManager::Status::NEED_INIT)
                         , _port(port)
                         , _address(QString().fromStdString(addr))
                         , _socket(new QTcpSocket()) {
        QObject::connect(_socket.get(), SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(_state_change(QAbstractSocket::SocketState)));
        QObject::connect(_socket.get(), SIGNAL(readyRead()), this, SLOT(recieve()));
    };

    void setHostAddress(const std::string& address) { _address = _address.fromStdString(address); }
    void setHostPort(uint16_t port) { _port = port; }


    // Copying is not available
    ClientSocket(const ClientSocket &other) = delete;

    ClientSocket &operator=(const ClientSocket &other) = delete;

    ~ClientSocket() override = default;

    void send(std::iostream &data) override {
        std::stringstream inBase;
        _base64.fromStream(data, inBase);
        wait_connected();
        QByteArray qdata(inBase.str().data(), inBase.str().size());
        _socket->write(qdata);
        _socket->flush();
    }

    void closeConnection() {
        _status = NEED_INIT;
        _socket->disconnectFromHost();
        emit disconnected();
    }

Q_SIGNALS:
    void disconnected();
public Q_SLOTS:
    void receive() override {
        QByteArray data = _socket->readAll();
        std::stringstream ss;
        ss.write(data.data(), data.size());
        std::stringstream fromBase;
        _base64.toStream(ss, fromBase);
        callback->callback(std::move(fromBase));
    }

    void init() {

        _status = OK;
        _socket->connectToHost(_address, _port);
    }

private Q_SLOTS:
    void _state_change(QAbstractSocket::SocketState state) {
        if (_status != NEED_INIT
            && state == QAbstractSocket::SocketState::UnconnectedState)
        {
            _status = NEED_INIT;
            emit disconnected();
        }
    }


private:
    void wait_connected() {
        while (_socket->state() == QAbstractSocket::SocketState::ConnectingState &&
               !_socket->waitForConnected());
        if (_socket->state() != QAbstractSocket::SocketState::ConnectedState)
            throw std::runtime_error("Client: couldn't connect to " + _address.toStdString() + ":" + std::to_string(_port));
        //TODO: handle disconnet during waiting
    }
};
}

#endif //HELLOWORLD_TRANSMISSION_NET_CLIENT_H
