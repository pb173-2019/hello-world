//
// Created by ivan on 11.4.19.
//

#ifndef HELLOWORLD_TRANSMISSION_NET_SERVER_H
#define HELLOWORLD_TRANSMISSION_NET_SERVER_H

#include <QObject>
#include <QtNetwork>
#include "../shared/transmission.h"
#include "../shared/utils.h"
#include "../shared/base_64.h"


namespace helloworld {
    class Connection : public QObject {
        Q_OBJECT

        Q_SIGNALS:

    };

    class ServerSocket : public QObject, public ServerTransmissionManager {
        Q_OBJECT
        Base64 _base64;
        // TODO: make it map / set for easier lookup
        std::vector<Connection> _connections;

    public:
        ServerSocket(
                Callable<void, bool, const std::string&, std::stringstream&&>* callback,
                QObject *parent = nullptr)
            : QObject(parent)
            ,
    };

} // helloworld

#endif //HELLOWORLD_TRANSMISSION_NET_SERVER_H
