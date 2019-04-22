
/**
 * @file transmission_net_server.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Transmission manager implementation
 *          temporary testing solution
 *
 * @version 0.1
 * @date 21. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
#define HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_

#include <fstream>
#include <sstream>
#include <set>
#include <cstring>

#include <QtCore>
#include <QtNetwork>
#include <QThread>
#include <qreadwritelock.h>
#include <QThreadStorage>

#include "../shared/transmission.h"
#include "../shared/base_64.h"
#include "../shared/utils.h"
#include "net_utils.h"

namespace helloworld {
class ServerTCP;

class ServerSocket : public QObject {
Q_OBJECT

    bool _owned = true;
    ServerTCP *server;
public:
    QTcpSocket *socket{nullptr};
    std::string username;

    explicit ServerSocket(QTcpSocket *socket, std::string username, ServerTCP * server, QObject *parent = nullptr);

    // Copying is not available
    ServerSocket(const ServerSocket &other) = delete;
    ServerSocket &operator=(const ServerSocket &other) = delete;

    ServerSocket(ServerSocket &&other);
    ServerSocket &operator=(ServerSocket &&other);

    ~ServerSocket() {
        if (_owned && socket)
            socket->deleteLater();
    }
public Q_SLOTS:
    /**
     * @brief receive data from socket
     */
    void receive();

    /**
     * @brief updateConnection check whether socket was disconnected
     * @param state new socket state
     */
    void updateConnection(QAbstractSocket::SocketState state);

    /**
     * @brief send data (slot so it can be called in sockets thread)
     * @param data to send
     */
    void send(QByteArray data);
Q_SIGNALS:
    /**
     * @brief disconnected signal on disconnect
     */
    void disconnected(const QTcpSocket *);
};

class SocketManager : public QObject {
    Q_OBJECT
    ServerTCP *server;
public:
    EventThread *thread; // Custom thread runing event loop
    std::vector<ServerSocket *> ownedSockets;
    QReadWriteLock lock;
    SocketManager(ServerTCP * server, QObject *parent = nullptr);
public slots:
    /**
     * @brief emplace new connection into thread
     * @param socket socket to store in thread
     * @param name username of user connected to socket
     */
    void emplace(QTcpSocket *socket, const std::string& name);
    /**
     * @brief remove socket from this thread
     * @param socket pointer to socket whic to remove
     * @return true on success false otherwise
     */
    bool remove(const QTcpSocket *socket);
    /**
     * @brief toRegister (just because std string cant be done by default)
     * @param socket
     * @param name
     */
    void toRegister(QTcpSocket *socket,const QString &name);
signals:
    /**
     * @brief removed signal called upon removal of socket
     */
    void removed(QString);
};

class ServerTCP : public QObject, public ServerTransmissionManager {
    friend ServerSocket;

    // must be destroyed after all threads finish (not before)
    static QThreadStorage<PtrWrap<QTcpSocket>> _lastSending;

    Q_OBJECT

    Base64 _base64;
    std::vector<std::unique_ptr<SocketManager>> _threads;
    QTcpServer _server;
public:
    QReadWriteLock lock;

public slots:

    /**
     * Called on new incomming connection
     */
    void discoverConnection();

    void updateConnection(QAbstractSocket::SocketState state);

    void receive() override;

private slots:
    /**
     * @brief cleanAfter just to allow simpler signal propagation
     *          about socket deletion to server
     * @param name associated with deleted socket
     */
    void cleanAfter(QString name);
    Q_SIGNALS:
    void conn(QHostAddress, quint16);
    void disconn(QHostAddress, quint16);

    void clossedConnection(QString);

    void toRegister(QTcpSocket *, QString);
    void forward(QByteArray);
public:
    explicit ServerTCP(Callable<void, bool, const std::string &, std::stringstream &&> *callback,
                       QObject *parent = nullptr);

    // Copying is not available
    ServerTCP(const ServerTCP &other) = delete;
    ServerTCP &operator=(const ServerTCP &other) = delete;
    ~ServerTCP() override = default;

    void send(const std::string &usrname, std::iostream &data) override;

    /**
     * Mark some connection as opened
     * @param connection
     */
    void registerConnection(const std::string &username) override;

    /**
     * Called when new connection fails -> server sends generic error and calls destructor
     * @param data data to send before discarding the connectino
     */
    void discardNewConnection(const std::vector<unsigned char> &data) override;
    /**
     * Release connection
     * @param connection7
     * @return true if connection deleted
     */
    bool removeConnection(const std::string &username) override;

    /**
     * Check filename for its connection
     * @param filename name to check
     * @return 0 if no connection found, otherwise >0
     */
    bool exists(const std::string &username);

    /**
     * Get names of all connected users
     * @return
     */
    //todo will return even auth-waiting users ! consider the consequence
    std::set<std::string> getOpenConnections() override;

private:

    SocketManager * minThread();

    void _receive(QTcpSocket *sender, const std::string& name = "");
    void _send(QTcpSocket *receiver, QByteArray& data);
    //todo maybe use hashmap or treemap - better than O(n)
    QTcpSocket *getSocket(const std::string &username);
    std::string getName(const QTcpSocket *client);
    void removeConnection(const QTcpSocket *client);
};

} //namespace helloworld

#endif //HELLOWORLD_SHARED_TRANSMISSION_FILE_SERVER_H_
