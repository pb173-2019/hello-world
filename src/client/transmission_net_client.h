/*
 * @file transmission_net_client.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief client network interface
 */

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
    QDataStream in;
public:
    explicit ClientSocket(Callable<void, std::stringstream &&> *callback,
                          std::string username, const std::string &addr = "",
                          uint16_t port = 5000, QObject *parent = nullptr);

    void setHostAddress(const std::string &address);

    void setHostPort(uint16_t port);

    // Copying is not available
    ClientSocket(const ClientSocket &other) = delete;

    ClientSocket &operator=(const ClientSocket &other) = delete;

    ~ClientSocket() override {
        QObject::disconnect(_socket.get(), SIGNAL(stateChanged(QAbstractSocket::SocketState)), this,
                            SLOT(_state_change(QAbstractSocket::SocketState)));
    };

    void send(std::iostream &data) override;

    void closeConnection();

Q_SIGNALS:

    void disconnected();

    void received();

    void sent();

public Q_SLOTS:

    void receive() override;

    void init();

    void onError(QAbstractSocket::SocketError socketError);

private Q_SLOTS:

    void _state_change(QAbstractSocket::SocketState state);

private:
    bool wait_connected();
};
}

#endif //HELLOWORLD_TRANSMISSION_NET_CLIENT_H
