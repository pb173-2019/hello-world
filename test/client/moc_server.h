//
// Created by ivan on 11.4.19.
//

#ifndef HELLOWORLD_MOC_SERVER_H
#define HELLOWORLD_MOC_SERVER_H

#include <QObject>
#include <QtNetwork>
#include <QByteArray>

#include <vector>
#include <memory>
#include <deque>
#include <sstream>
#include <functional>

#include <cstdint>
#include <iostream>

#include "../../src/shared/base_64.h"

namespace helloworld {
    namespace detail {
        struct Connection : public QObject {
            Q_OBJECT
                    QTcpSocket *_socket;

            Base64 _base;
        public:
            Connection(QTcpSocket *socket, QObject *parent = nullptr)
                    : QObject(parent), _socket(socket) {
                QObject::connect(socket, SIGNAL(readyRead()), this, SLOT(read()));
                QObject::connect(socket, SIGNAL(disconnected()), this,
                                 SLOT(closing()));
            }

            ~Connection() = default;

            void send(std::istream&& data)  {
                std::stringstream out;
                _base.fromStream(data, out);
                out << '\0';
                QByteArray qdata = QByteArray::fromStdString(out.str());

                _socket->write(qdata);
                _socket->flush();
            }

            Q_SIGNALS:

            void messageRecieved(Connection*, std::string);

            void closed(Connection *);

        public Q_SLOTS:

                    void read() {
                QByteArray data = _socket->readAll();
                emit messageRecieved(this, data.toStdString());
                //emit closing(this);
            };

            void closing() {
                if(_socket->state() != QAbstractSocket::SocketState::ClosingState
                || _socket->state() != QAbstractSocket::SocketState::UnconnectedState)
                    _socket->disconnectFromHost();
                emit closed(this);
            }

        };



        class MocServer : public QObject {
        Q_OBJECT


            std::vector<Connection *> _connections;


            int counter, target;

            quint16 _port;
            QHostAddress _address;

            // OnConnection
            std::function<void(MocServer*, Connection*)> connectionCallback;
            // on message
            std::function<void(Connection *, std::string)> messageCallback;

            std::unique_ptr<QTcpServer> _server;
            Base64 _base;
        public:
            std::deque<std::string> recieved;
            MocServer(qint16 port = 5000, QHostAddress address = QHostAddress::Any)
                    : QObject(nullptr),counter(0), target(INT_MAX), _port(port), _address(address),
                    connectionCallback([](MocServer*, Connection *) {}),
                    messageCallback([](Connection *, std::string) {}),
                    _server(new QTcpServer()) {
                QObject::connect(_server.get(), SIGNAL(newConnection()), this, SLOT(onConnection()));
            }
            ~MocServer() = default;

            int getConnectionCounter() { return counter; }

            void setMaxConnections(int max) {
                target = max;
            }
            void setConnectionCallback(std::function<void(MocServer*, Connection*)> &&foo) {
                connectionCallback = std::move(foo);
            }

            void setMessageCallback(std::function<void(Connection *, std::string)>  &&foo) {
                messageCallback = std::move(foo);
            }

            void close() {
                emit finished();
            }

        Q_SIGNALS:

            void finished();

        public Q_SLOTS:
            void messageRecieved(Connection *src, std::string s) {
            std::stringstream ss(s);
            std::string line;
            while(!std::getline(ss, line, '\0').eof()) {
                std::stringstream in(line), out{};
                _base.toStream(in, out);
                recieved.push_back(std::move(out.str()));
                messageCallback(src, out.str());
            }
            };

            void onConnection() {
                _connections.emplace_back(new Connection(_server->nextPendingConnection(), this));
                auto pLast = _connections.back();
                QObject::connect(
                        pLast,
                        SIGNAL(messageRecieved(Connection*, std::string)),
                        this,
                        SLOT(messageRecieved(Connection*, std::string)));
                QObject::connect(pLast, SIGNAL(closed(Connection *)), this, SLOT(connectionClosed(Connection *)));

                connectionCallback(this, pLast);
                if (++counter >= target) {
                    emit finished();
                }

            };
            void connectionClosed(Connection *connection) {
                auto it = std::find_if(
                        _connections.begin(),
                        _connections.end(),
                        [connection](const auto& obj) { return connection == obj; }
                );
                if (it == _connections.end())
                    return;


                disconnect(*it, SIGNAL(closed(Connection *)), this, SLOT(connectionClosed(Connection *)));
                _connections.erase(it);

            };
            void start() {
                if (!_server->listen(_address, _port))
                    std::runtime_error("Cannot start test server");
            }

        private Q_SLOTS:

        };

        class RequireEmitted : public QObject {
            Q_OBJECT
        public:

            bool emmited{false};
            RequireEmitted() : QObject(nullptr) {}


        public Q_SLOTS:

            void done() {
                emmited = true;
            };
        };
    }
}


#endif //HELLOWORLD_MOC_SERVER_H
