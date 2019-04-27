#ifndef HELLOWORLD_NET_H
#define HELLOWORLD_NET_H

#include <QObject>
#include <memory>

#include "conf.h"

#include "../../src/client/client.h"
#include "../../src/client/transmission_net_client.h"

using namespace helloworld;

//RUN SETUP TARGET FIRST TO GENERATE RSA KEYS !!!!
// THIS IS SEPARATED AS THE KEY GENERATING WOULD POLLUTE THE PROFILING

class ClientPerformer : public QObject {
Q_OBJECT
public:
    Client c;
    std::string pubKey;

    ClientPerformer(const std::string& name, const std::string& key, const std::string& pub, const std::string& pwd, QObject* parent = nullptr)
        : QObject(parent), c(name, key, pwd), pubKey(pub) {

        c.setTransmissionManager(std::make_unique<ClientSocket>(&c, c.name()));
    }

    ~ClientPerformer() override = default;

public slots:

    void reg() {
        connect();
        c.createAccount(pubKey);
    };

    void send(uint32_t id) {
        c.sendData(id, {1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,2,3,1,3,1,2,1,32,1,3,2});
    }

    void updateKeys() {
        c.sendKeysBundle();
    }

    void getOnline() {
        c.sendGetOnline();
    }

    void findByName() {
       c.sendFindUsers("alice");
    }

    void logout() {
        c.logout();
        disconnect();
    }

    void login() {
        connect();
        c.login();
    }

    void deleteAcc() {
        c.deleteAccount();
        disconnect();
    }

    uint32_t getId() {
        return c.getId();
    }

private:
    void disconnect() {
        auto clientSocket = dynamic_cast<ClientSocket *>(c.getTransmisionManger());
        if (clientSocket != nullptr) {
            clientSocket->closeConnection();
        } else {
            throw std::runtime_error("Failed to disconnect");
        }
    }

    void connect() {
        auto clientSocket = dynamic_cast<ClientSocket *>(c.getTransmisionManger());
        clientSocket->init();
    }
};

class ClientCaller : public QObject {
Q_OBJECT
public:
    ~ClientCaller() override = default;

signals:
    void reg();
    void send(uint32_t id);
    void updateKeys();
    void getOnline();
    void findByName();
    void logout();
    void login();
    void deleteAcc();
    uint32_t getId();
};

#endif
