


#include <sstream>
#include <QObject>
#include <QtNetwork>
#include <QDataStream>
#include <cstdint>
#include <memory>
#include "transmission_net_client.h"
#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"
using namespace helloworld;

ClientSocket::ClientSocket(Callable<void, std::stringstream &&> *callback,
                              std::string username,
                              const std::string& addr,
                              uint16_t port, QObject *parent)
                : QObject(parent)
                , UserTransmissionManager(callback, std::move(username), UserTransmissionManager::Status::NEED_INIT)
                , _port(port)
                , _address(QString().fromStdString(addr))
                , _socket(new QTcpSocket(this)) {
            QObject::connect(_socket.get(), SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(_state_change(QAbstractSocket::SocketState)));
            connect(_socket.get(), SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(onError(QAbstractSocket::SocketError)));
            connect(_socket.get(), SIGNAL(readyRead()), this, SLOT(receive()));

        };

        void ClientSocket::setHostAddress(const std::string& address) { _address = _address.fromStdString(address); }
        void ClientSocket::setHostPort(uint16_t port) { _port = port; }


        void ClientSocket::send(std::iostream &data)  {
            std::stringstream inBase;
            _base64.fromStream(data, inBase);
            inBase << '\0';
            if (!wait_connected())
                return;
            QByteArray qdata(inBase.str().data(), inBase.str().size());
            _socket->write(qdata);
            _socket->flush();
        }

        void ClientSocket::closeConnection() {
            _status = NEED_INIT;
            _socket->disconnectFromHost();
            emit disconnected();
        }


        void ClientSocket::onError(QAbstractSocket::SocketError socketError) {
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
        }

        void ClientSocket::init() {

            _status = OK;
            _socket->connectToHost(_address, _port);
            _socket->waitForConnected();
        }

        void ClientSocket::_state_change(QAbstractSocket::SocketState state) {

            if (_status != NEED_INIT
                && state == QAbstractSocket::SocketState::UnconnectedState)
            {
                _status = NEED_INIT;
                emit disconnected();
            }
        }

        bool ClientSocket::wait_connected() {
            while (_socket->state() == QAbstractSocket::SocketState::ConnectingState &&
                   !_socket->waitForConnected());

            if (_socket->state() != QAbstractSocket::SocketState::ConnectedState) {
                if (_status != NEED_INIT) {
                    _status = NEED_INIT;
                    emit disconnected();
                }
                return false;
            }
            return true;
            //TODO: handle disconnet during waiting
        }


