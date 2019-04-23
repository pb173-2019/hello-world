/*
 * @file log_app.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief main server application
 *
 */

#ifndef HELLOWORLD_LOG_APP_H
#define HELLOWORLD_LOG_APP_H

#include <QObject>
#include <memory>
#include <QMutex>

#include "server.h"
#include "transmission_net_server.h"

namespace helloworld {
    class LogApp : public QObject {
    Q_OBJECT
        std::ostream &os;
        std::unique_ptr<Server> server;
        QMutex mutex;
        bool logThread{true};
    public:
        /**
         * @brief LogApp main runtime application for server
         * @param os standard output stream
         * @param parent QT requirement
         */
        LogApp(std::ostream &os, QObject *parent = nullptr)
                : QObject(parent)
                , os(os)
                , server(std::make_unique<Server>()){

            server->setTransmissionManager(std::make_unique<ServerTCP>(server.get()));

            auto ptr = dynamic_cast<ServerTCP *> (server->getTransmisionManger());
            assert(ptr);
            connect(ptr, SIGNAL(conn(QHostAddress, quint16)), this, SLOT(onConnection(QHostAddress, quint16)));
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

        /**
         * @brief log logs message in thread safe way
         * @param logmsg message to log
         */
        void log(const std::string& logmsg) {
            QMutexLocker lock(&mutex);
            if (logThread)
                os << "(thread#"<< QThread::currentThreadId() << ") " ;
            os << logmsg << '\n';
        }

        ~LogApp() { os << "closing App\n"; }

    public Q_SLOTS:
        /**
         * @brief onConnection slot called when server emits connection signal
         * @param addr ip address of connected user
         * @param port port of connected user
         */
        void onConnection(QHostAddress addr, quint16 port) {

            os << "Connection from " << toStd(addr)
                << ":" << port << "\n";
        }
        /**
         * @brief onDisconnect called on disconnection of user
         * @param addr address of disconnected user
         * @param port port of disconnected user
         */
        void onDisconnect(QHostAddress addr, quint16 port) {
            os << "Disconnected from " << toStd(addr)
               << ":" << port << "\n";
        }

     /**
     * @brief toStd extracts ip addres from host address structure
     * @param host address to extract ip from
     * @return ip address
     */
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
