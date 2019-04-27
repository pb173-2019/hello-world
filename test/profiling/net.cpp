#include "net.h"

#include <QThread>
#include <chrono>
#include <thread>
#include <stdlib.h>

#include "conf.h"

#include "../../src/server/server.h"
#include "../../src/server/net_utils.h"
#include "../../src/server/transmission_net_server.h"
#include "../../src/server/log_app.h"

using namespace helloworld;

//RUN SETUP TARGET FIRST TO GENERATE RSA KEYS !!!!
// THIS IS SEPARATED AS THE KEY GENERATING WOULD POLLUTE THE PROFILING

void initClient(int argc, char *argv[],
        std::vector<ClientPerformer*>* clients,
        const std::string& name,
        const std::string& privateKey,
        const std::string& pubKey,
        const std::string& pwd,
        const std::string& address) {

    QEventLoop thread;
    ClientPerformer performer(name, privateKey, pubKey, pwd, &thread);

    auto clientSocket = dynamic_cast<ClientSocket *>(performer.c.getTransmisionManger());

    if (clientSocket != nullptr) {
        clientSocket->setHostAddress(address);
        QObject::connect(clientSocket, SIGNAL(disconnected()), &thread, SLOT(quit()));
    }

//    QObject::connect(caller, SIGNAL(reg()), &performer, SLOT(reg()));
//    QObject::connect(caller, SIGNAL(send(uint32_t)), &performer, SLOT(send(uint32_t)));
//    QObject::connect(caller, SIGNAL(updateKeys()), &performer, SLOT(updateKeys()));
//    QObject::connect(caller, SIGNAL(getOnline()), &performer, SLOT(getOnline()));
//    QObject::connect(caller, SIGNAL(findByName()), &performer, SLOT(findByName()));
//    QObject::connect(caller, SIGNAL(logout()), &performer, SLOT(logout()));
//    QObject::connect(caller, SIGNAL(login()), &performer, SLOT(login()));
//    QObject::connect(caller, SIGNAL(deleteAcc()), &performer, SLOT(deleteAcc()));
//    QObject::connect(caller, SIGNAL(getId()), &performer, SLOT(getId()));
    clients->push_back(&performer);

    thread.exec();
}

void startServer(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    LogApp log(std::cout, &app);
    app.exec();
}

int main(int argc , char ** argv) {
    qRegisterMetaType<uint32_t>("uint32_t");

    std::thread t(startServer, argc, argv);

    std::string address;
    QList<QHostAddress> list = QNetworkInterface::allAddresses();
    for (int nIter = 0; nIter < list.count(); nIter++) {
        if (!list[nIter].isLoopback())
            if (list[nIter].protocol() == QAbstractSocket::IPv4Protocol)
                address = list[nIter].toString().toStdString();
    }
    assert(!address.empty());

    std::cout << "Waiting for server to catch up...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    std::vector<ClientPerformer* >clients;

//    ClientCaller c0;
    std::thread t0(initClient, argc, argv, &clients, "0alice", "alice_0_priv.pem", "alice_0_.pem", "1234", address);
//    ClientCaller c1;
    std::thread t1(initClient, argc, argv, &clients, "1alice", "alice_1_priv.pem", "alice_1_.pem", "1234", address);

    if (ROUNDS != 20) throw Error("Invalid number of rounds."); //prevence from bad setup in conf.h

    uint32_t bobId;
    QGenericArgument userId{"uint32_t", &bobId};
    QGenericReturnArgument getUserId{"uint32_t", &bobId};
    QGenericArgument noArg{"", nullptr};
    QGenericReturnArgument noRet{"", nullptr};

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    QMetaObject::invokeMethod(clients[0], "reg", Qt::BlockingQueuedConnection, noRet);
    QMetaObject::invokeMethod(clients[1], "reg", Qt::BlockingQueuedConnection, noRet);

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    system("Color F3");
    std::cout << "\n\nPress enter to start profiling.\n";
    std::cin.ignore();

    //20 times message
    QMetaObject::invokeMethod(clients[1], "getId", Qt::BlockingQueuedConnection, getUserId); //get Bob Id
    QMetaObject::invokeMethod(clients[0], "send", Qt::BlockingQueuedConnection, noRet, userId); //use Bob Id

    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    for (int i = 0; i < ROUNDS; i++) {
        QMetaObject::invokeMethod(clients[0], "send", Qt::BlockingQueuedConnection, noRet, userId);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // ROUNDS times update key bundle
    for (int i = 0; i < ROUNDS; i++) {
        QMetaObject::invokeMethod(clients[0], "updateKeys", Qt::BlockingQueuedConnection, noRet);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // ROUNDS times getOnline
    for (int i = 0; i < ROUNDS; i++) {
        QMetaObject::invokeMethod(clients[0], "getOnline", Qt::BlockingQueuedConnection, noRet);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // ROUNDS times get user by name
    for (int i = 0; i < ROUNDS; i++) {
        QMetaObject::invokeMethod(clients[0], "findByName", Qt::BlockingQueuedConnection, noRet);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // ROUNDS times logout - does not work -_-
//    for (int i = 0; i < ROUNDS; i++) {
//        QMetaObject::invokeMethod(clients[1], "logout", Qt::BlockingQueuedConnection, noRet);
//        std::this_thread::sleep_for(std::chrono::milliseconds(250));
//        QMetaObject::invokeMethod(clients[1], "login", Qt::BlockingQueuedConnection, noRet);
//        std::this_thread::sleep_for(std::chrono::milliseconds(250));
//    }
    QMetaObject::invokeMethod(clients[0], "deleteAcc", Qt::BlockingQueuedConnection, noRet);
    QMetaObject::invokeMethod(clients[1], "deleteAcc", Qt::BlockingQueuedConnection, noRet);

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    t.detach();
    t0.detach();
    t1.detach();

    ClientCleaner_Run();
}