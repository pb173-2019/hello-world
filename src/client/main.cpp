#include <iostream>

#include <QObject>
#include <QCoreApplication>
#include <QThread>
#include "../shared/rsa_2048.h"
#include "client.h"
#include "CMDapp.h"
using namespace helloworld;



int main(int argc , char ** argv ) {
    QCoreApplication a(argc, argv);
    // T
    QThread CMDThread;
    CMDApp mainApp(std::cin, std::cout);

    QObject::connect(&CMDThread, SIGNAL(finished()), &a, SLOT(quit()));
    QObject::connect(&CMDThread, SIGNAL(started()), &mainApp, SLOT(init()));
    QObject::connect(&mainApp, SIGNAL(close()), &CMDThread, SLOT(quit()));

    mainApp.moveToThread(&CMDThread);
    CMDThread.start(QThread::Priority::NormalPriority);


    return a.exec();
}
