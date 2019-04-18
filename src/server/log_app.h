//
// Created by shockudt on 14.4.19.
//

#ifndef HELLOWORLD_LOG_APP_H
#define HELLOWORLD_LOG_APP_H

#include <QObject>
#include <memory>

#include "server.h"
#include "transmission_net_server.h"


namespace helloworld {
    class LogApp : public QObject {
    Q_OBJECT
        std::ostream &os;
        std::unique_ptr<Server> server;
    public:
        LogApp(std::ostream &os, QObject *parent = nullptr)
                : QObject(parent)
                , os(os)
                , server(std::make_unique<Server>()){

            server->setTransmissionManager(std::make_unique<ServerTCP>(server.get()));

            auto ptr = dynamic_cast<ServerTCP *> (server->getTransmisionManger());
            assert(ptr);
            connect(ptr, SIGNAL(conn(QHostAddress, quint16)), this, SLOT(onConnection(QHostAddress, quint16)));
            connect(ptr, SIGNAL(sent(QHostAddress, quint16)), this, SLOT(onSend(QHostAddress, quint16)));
            connect(ptr, SIGNAL(recieved(QHostAddress, quint16)), this, SLOT(onReceive(QHostAddress, quint16)));
            connect(ptr, SIGNAL(disconn(QHostAddress, quint16)), this, SLOT(onDisconnect(QHostAddress, quint16)));
            connect(ptr, &ServerTCP::clossedConnection, server.get(), &Server::cleanAfterConenction);

            os << "listening on ";
            QList<QHostAddress> list = QNetworkInterface::allAddresses();

            for(int nIter=0; nIter<list.count(); nIter++)

            {
                if(!list[nIter].isLoopback())
                    if (list[nIter].protocol() == QAbstractSocket::IPv4Protocol )
                        os << list[nIter].toString().toStdString();

            }
            os << "\n";

            server->setLogging([this](const std::string& msg) { log(msg); });
        }

        void log(const std::string& logmsg) {
            os << logmsg << std::endl;
        }

        ~LogApp() { os << "closing App\n"; }

    public Q_SLOTS:
        void onConnection(QHostAddress addr, quint16 port) {

            os << "Connection from " << toStd(addr)
                << ":" << port << "\n";
        };
        void onSend(QHostAddress addr, quint16 port) {
            os << "Sent message to " << toStd(addr)
               << ":" << port << "\n";
        };
        void onReceive(QHostAddress addr, quint16 port) {
            os << "Received message from " << toStd(addr)
               << ":" << port << "\n";
        };

        void onDisconnect(QHostAddress addr, quint16 port) {
            os << "Disconnected from " << toStd(addr)
               << ":" << port << "\n";
        };

    std::string toStd(QHostAddress& host) {
        bool conversionOK = false;
        QHostAddress ip4Address(host.toIPv4Address(&conversionOK));
        QString ip4String;
        if (conversionOK)
        {
            return ip4Address.toString().toStdString();
        }
        return host.toString().toStdString();
    }
    };

}
#endif //HELLOWORLD_LOG_APP_H
