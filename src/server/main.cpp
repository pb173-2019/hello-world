#include <iostream>
#include <sstream>
#include <QCoreApplication>

#include "log_app.h"
using namespace helloworld;

int main(int argc , char ** argv) {
    QCoreApplication a(argc, argv);
    LogApp log(std::cout, &a);
    return a.exec();
}
