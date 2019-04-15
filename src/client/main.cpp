#include <iostream>

#include <QObject>
#include <QCoreApplication>
#include <QTimer>
#include "../shared/rsa_2048.h"
#include "client.h"
#include "CMDapp.h"
using namespace helloworld;


int main(int argc , char ** argv ) {
    QCoreApplication a(argc, argv);
    CMDApp * mainApp = new CMDApp(std::cin, std::cout, &a);
    QTimer *t = new QTimer(&a);
    t->setInterval(10);
    QObject::connect(t, SIGNAL(timeout()), mainApp, SLOT(_loop()));
    QObject::connect(mainApp, SIGNAL(close()), &a, SLOT(quit()));
    QObject::connect(mainApp, SIGNAL (close()), mainApp, SLOT (deleteLater()));

    t->start();
    return a.exec();
}
