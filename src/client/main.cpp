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
    CMDApp * mainApp = new CMDApp(&a);
    cinPoll * poll = new cinPoll(mainApp->window, &a);

    QObject::connect(poll, &cinPoll::read, mainApp, &CMDApp::_loop);
    QObject::connect(mainApp, &CMDApp::poll, poll, &cinPoll::start);
    QObject::connect(mainApp, SIGNAL(close()), &a, SLOT(quit()));
    QObject::connect(mainApp, SIGNAL (close()), mainApp, SLOT (deleteLater()));

    mainApp->init();
    return a.exec();
}
