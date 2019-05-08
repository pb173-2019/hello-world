#include <QCoreApplication>
#include <iostream>
#include <sstream>

#include "log_app.h"
using namespace helloworld;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Wrong number of arguments\n"
                     "./server password\n";
        return 1;
    }

    QCoreApplication a(argc, argv);
    LogApp log(std::cout, argv[1], &a);
    return a.exec();
}
