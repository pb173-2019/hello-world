/*
 * @file transmission_net_client.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief client network interface
 */

#ifndef HELLOWORLD_TRANSMISSION_NET_CLIENT_H
#define HELLOWORLD_TRANSMISSION_NET_CLIENT_H

#include <QObject>
#include <QtNetwork>
#include <cstdint>
#include <memory>
#include <sstream>
#include "../shared/base_64.h"
#include "../shared/transmission.h"
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

    ClientSocket(const ClientSocket &other) = delete;
    ClientSocket &operator=(const ClientSocket &other) = delete;

    ~ClientSocket() override {
        QObject::disconnect(
            _socket.get(), SIGNAL(stateChanged(QAbstractSocket::SocketState)),
            this, SLOT(_state_change(QAbstractSocket::SocketState)));
    };

    /**
     * Setup host address to connect to
     *
     * &param address ipv4 address in <>.<>.<>.<> form
     */
    void setHostAddress(const std::string &address);

    /**
     * Set port to use
     * @param port port number to use
     */
    void setHostPort(uint16_t port);

    void send(std::iostream &data) override;

    /**
     * Closes the connection, the socked is closed and
     * the disconnected() signal emmited
     */
    void closeConnection();

   Q_SIGNALS:

    /**
     * Signal emmited on disconnect
     */
    void disconnected();

    /**
     * Signal emmited on response receive
     */
    void received();

    /**
     * Signal emmited on request send
     */
    void sent();

   public Q_SLOTS:

    /**
     * Function receiving the received signal
     */
    void receive() override;

    /**
     * Function receiving the starting signal
     */
    void init();

    /**
     * Function receiving any error signals
     * @param socketError
     */
    void onError(QAbstractSocket::SocketError socketError);

   private Q_SLOTS:

    /**
     * Receives the changed state event, which is
     * usually the disconnection itslef
     * @param state new socket state
     */
    void _state_change(QAbstractSocket::SocketState state);

   private:
    bool wait_connected();
};

}    // namespace helloworld

#endif    // HELLOWORLD_TRANSMISSION_NET_CLIENT_H
