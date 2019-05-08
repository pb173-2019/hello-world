//
// Created by Ivan Mitruk on 15.4.19.
//

#ifndef HELLOWORLD_TEST_SERVER_NET_H
#define HELLOWORLD_TEST_SERVER_NET_H

#include <QObject>
#include <QtNetwork>
#include <deque>
#include <functional>
#include <memory>
#include <sstream>
#include "../../src/server/transmission_net_server.h"
#include "../../src/shared/base_64.h"
#include "../../src/shared/utils.h"
namespace helloworld {
struct MocClient : public QObject {
    Q_OBJECT
   public:
    Base64 _base;
    std::unique_ptr<QTcpSocket> socket{std::make_unique<QTcpSocket>(this)};
    std::deque<std::string> received{};
    std::function<void(std::string)> onMessageRecieved{[](std::string /**/) {}};
    std::function<void(MocClient*)> onConnect{[](MocClient* /**/) {}};
    void connect(std::string ip, uint16_t port) {
        socket->connectToHost(QHostAddress(QString().fromStdString(ip)), port);
        QObject::connect(socket.get(), SIGNAL(readyRead()), this,
                         SLOT(receive()));
        QObject::connect(socket.get(), SIGNAL(disconnected()), this,
                         SLOT(disconnect()));

        if (!socket->waitForConnected()) {
            throw std::runtime_error("couldnt connect");
        }
        emit conn();
        onConnect(this);
    }
    void send(std::string msg) {
        std::stringstream data{msg}, inBase;
        _base.fromStream(data, inBase);
        inBase << '\0';    // to different distinguish messages
        QByteArray qdata(inBase.str().data(), inBase.str().size());
        socket->write(qdata);
        socket->flush();
        emit sent();
    }

   Q_SIGNALS:
    void conn();
    void sent();
    void recv();
    void disc();

   public Q_SLOTS:
    void receive() {
        QByteArray data = socket->readAll();
        std::stringstream ss(data.toStdString());
        std::string line;
        while (!std::getline(ss, line, '\0').eof()) {
            std::stringstream inBase(line), fromBase{};
            _base.toStream(inBase, fromBase);
            onMessageRecieved(fromBase.str());
            received.emplace_back(fromBase.str());
            emit recv();
        }
    };
    void disconnect() {
        if (socket->state() == QAbstractSocket::SocketState::ConnectedState) {
            socket->disconnectFromHost();
            socket->waitForDisconnected();
        }
        emit disc();
    }
};

struct RecquireEmmited : public QObject {
    Q_OBJECT
   public:
    bool emmited{false};
   Q_SIGNALS:
    void recv();
   public Q_SLOTS:
    void onEmmit() {
        emmited = true;
        emit recv();
    }

    void onTimer() { emit recv(); }
};

struct signalReaction : public QObject {
    Q_OBJECT
   public:
    std::function<void()> foo;
   public Q_SLOTS:

    void onEmmit(QHostAddress, quint16) { foo(); }
    void onEmmit() { foo(); }
};

struct noCallback
    : public Callable<void, bool, const std::string&, std::stringstream&&> {
    void callback(bool, const std::string&, std::stringstream&& /*unused*/) {}
};

struct messageStorage
    : public QObject,
      public Callable<void, bool, const std::string&, std::stringstream&&> {
    Q_OBJECT
   public:
    std::deque<std::pair<std::string, std::string> > received;
    int counter{1};
    void callback(bool, const std::string& name, std::stringstream&& ss) {
        received.emplace_back(name, ss.str());
        counter--;
        if (counter == 0) {
            emit done();
        }
    }

   Q_SIGNALS:
    void done();
};

struct EchoCallback
    : public Callable<void, bool, const std::string&, std::stringstream&&> {
    ServerTCP* server;
    const std::vector<std::string>* names{nullptr};
    std::vector<std::string>::const_iterator it;
    void callback(bool, const std::string& name, std::stringstream&& ss) {
        if (names) {
            if (it == std::vector<std::string>::iterator())
                it = names->begin();
            else
                ++it;
            server->registerConnection(*it);

            server->send(*it, ss);
        } else {
            server->send(name, ss);
        }
    }
};

struct RegOnFirstMsg
    : public QObject,
      public Callable<void, bool, const std::string&, std::stringstream&&> {
    Q_OBJECT
   public:
    ServerTCP* server;
    std::deque<std::pair<std::string, std::string> > received;
    int counter{1};

    void callback(bool registered, const std::string& name,
                  std::stringstream&& ss) {
        if (!registered) {
            server->registerConnection(ss.str());
        } else {
            received.emplace_back(name, ss.str());
            counter--;
            if (counter == 0) {
                emit done();
            }
        }
    }

   signals:
    void done();
};
}    // namespace helloworld

#endif    // HELLOWORLD_TEST_SERVER_NET_H
