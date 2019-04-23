//
// Created by Ivan Mitruk on 15.4.19.
//

#include <QCoreApplication>
#include <deque>

#include "test_server_net.h"
#include "catch.hpp"
#include "../../src/server/transmission_net_server.h"

using namespace helloworld;
constexpr int timelimit_per_test = 10;
constexpr const char* localhost = "127.0.0.1";
void server_recieve_1ucnm(int n, std::string msg) {
    SECTION("1 unregistered client sending " + std::to_string(n) + "x" + msg) {
        int argc = 0;
        char name[] = "Test";
        char *argv[] = {name, NULL};
        QCoreApplication a{argc, argv};

        messageStorage call;
        ServerTCP server(&call);
        MocClient client;
        client.onConnect = [&](MocClient *c) {
            for(int i = 0; i < n; i++)
                c->send(msg);
        };
        call.counter = n;

        QObject::connect(&call, SIGNAL(done()), &a, SLOT(quit()));
        REQUIRE_NOTHROW(client.connect(localhost, 5000));

        QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));
        a.exec();
        CHECK(call.received.size() == n);
        for (auto & i : call.received)
            CHECK(i.second == msg);
    }
}


void server_recieve_1rcnm(int n, std::string name,std::string msg) {
    SECTION("1 registered client sending " + std::to_string(n) + "x" + msg) {
        int argc = 0;
        char name[] = "Test";
        char *argv[] = {name, NULL};
        QCoreApplication a{argc, argv};

        RegOnFirstMsg call;
        ServerTCP server(&call);
        call.server = &server;
        MocClient client;
        call.counter = n;

        signalReaction r;
        r.foo = [&]() {

            for (int i = 0; i < n; ++i) {
                client.send(msg);
            }
        };

        QObject::connect(&server, SIGNAL(recieved(QHostAddress, quint16 )), &r, SLOT(onEmmit(QHostAddress, quint16 )));

        QObject::connect(&call, SIGNAL(done()), &a, SLOT(quit()));
        REQUIRE_NOTHROW(client.connect(localhost, 5000));

        client.send(name);
        QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));

        a.exec();
        CHECK(call.received.size() == n);
        for (auto & i : call.received) {
            CHECK(i.first == name);
            CHECK(i.second == msg);
        }
    }
}

void server_send_1rcnm(int n, std::string name,std::string msg) {
    SECTION("1 registered client recieving " + std::to_string(n) + "x" + msg) {
        int argc = 0;
        char name[] = "Test";
        char *argv[] = {name, NULL};
        QCoreApplication a{argc, argv};

        RegOnFirstMsg call;
        ServerTCP server(&call);
        call.server = &server;
        MocClient client;
        call.counter = n;

        signalReaction r;
        r.foo = [&]() {
            for (int i = 0; i < n; ++i){
                std::stringstream out{msg};
                server.send(name, out);
            }
        };

        //QObject::connect(&server, SIGNAL(recieved(QHostAddress, quint16 )), &r, SLOT(onEmmit(QHostAddress, quint16 )));

        QObject::connect(&call, SIGNAL(done()), &a, SLOT(quit()));

        client.onMessageRecieved = [&, c = 0](std::string s) mutable {  ++c; if (c == n) a.quit(); };

        REQUIRE_NOTHROW(client.connect(localhost, 5000));
        client.send(name);
        QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));

        a.exec();
        CHECK(client.received.size() == n);
        for (auto & i : client.received) {
            CHECK(i == msg);
        }
    }
}


void server_send_1ucnm(int n, std::string msg) {
    SECTION("1 unregistered client receiving " + std::to_string(n) + "x" + msg) {
        int argc = 0;
        char name[] = "Test";
        char *argv[] = {name, NULL};
        QCoreApplication a{argc, argv};

        noCallback call;
        ServerTCP server(&call);
        MocClient client;

        signalReaction r;
        r.foo = [&]() {
            for (int i = 0; i < n; ++i) {
                std::stringstream out{msg};
                server.send("", out);
            }
        };

        client.onMessageRecieved = [&, c = 0](std::string s) mutable {  ++c; if (c == n) a.quit(); };
        QObject::connect(&server, SIGNAL(conn(QHostAddress, quint16 )), &r, SLOT(onEmmit(QHostAddress, quint16 )));

        REQUIRE_NOTHROW(client.connect(localhost, 5000));
        QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));

        a.exec();
        CHECK(client.received.size() == n);
        for (auto & i : client.received) {
            CHECK(i == msg);
        }
    }
}


void nrclients_echo(std::vector<std::string> names, std::string msg) {
    SECTION("ehoing messages of "+ std::to_string(names.size()) + " users") {
        int argc = 0;
        char name[] = "Test";
        char *argv[] = {name, NULL};
        QCoreApplication a{argc, argv};

        EchoCallback call;
        ServerTCP server(&call);
        call.server = &server;
        call.names = &names;

        signalReaction onEcho;
        onEcho.foo = [&a, n = names.size(), i = 0]() mutable {
            ++i;
            if (i == n) {
                a.quit();
            }
        };

        std::vector<std::unique_ptr<MocClient>> clients;
        clients.reserve(names.size());
        for (auto &i : names) {
            clients.emplace_back(std::make_unique<MocClient>());
            auto client = clients.back().get();
            client->onConnect = [&msg](MocClient *c){
                c->send(msg);
            };
            QObject::connect(client, SIGNAL(recv()), &onEcho, SLOT(onEmmit()));
            REQUIRE_NOTHROW(client->connect(localhost, 5000));
        }


        QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));

        a.exec();
        CHECK(clients.size() == names.size());
        for (auto & i : clients) {
            CHECK(i->received.size() == 1);
            CHECK(i->received.front() == msg);
        }
    }
}

TEST_CASE("connect and send message") {
    int argc = 0;
    char name[] = "Test";
    char *argv[] = {name, nullptr};
    QCoreApplication a{argc, argv};

    std::string msg;
    SECTION("short message") {
        msg = "O";
    }
    SECTION("normal length message") {
        msg = "Hello";
    }
    SECTION("super long message") {
        msg = std::string(1000, 'a');
    }

    messageStorage call;
    ServerTCP server(&call);
    MocClient client;
    client.onConnect = [&msg](MocClient *c) {
        c->send(msg);
    };
    QObject::connect(&call, SIGNAL(done()), &a, SLOT(quit()));
    REQUIRE_NOTHROW(client.connect(localhost, 5000));

    QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));

    a.exec();
    CHECK(call.received.size() == 1);
    CHECK(call.received.front().second == msg);

}

TEST_CASE("connect and receive message") {
    int argc = 0;
    char name[] = "Test";
    char *argv[] = {name, nullptr};
    QCoreApplication a{argc, argv};

    std::string msg;
    SECTION("short message") {
        msg = "O";
    }
    SECTION("normal length message") {
        msg = "Hello";
    }
    SECTION("super long message") {
        msg = std::string(1000, 'a');
    }



    noCallback call;
    ServerTCP server(&call);
    MocClient client;

    RecquireEmmited e;
    signalReaction r;
    r.foo = [&server, &msg]() {
        std::stringstream out{msg};
        server.send("", out);
    };
    QObject::connect(&server, SIGNAL(conn(QHostAddress, quint16 )), &r, SLOT(onEmmit(QHostAddress, quint16 )));


    client.onMessageRecieved = [&msg](std::string s) {
        CHECK(s==msg);
    };

    QObject::connect(&client, SIGNAL(recv()), &e, SLOT(onEmmit()));
    QObject::connect(&e, SIGNAL(recv()), &a, SLOT(quit()));

    QTimer::singleShot(10000, &e, SLOT(onTimer()));
    REQUIRE_NOTHROW(client.connect(localhost, 5000));

    QTimer::singleShot(timelimit_per_test * 1000, &a, SLOT(quit()));
    a.exec();
    CHECK(e.emmited);

}

TEST_CASE("unregistered send multiple messages") {
    server_send_1ucnm(2, std::string(200, 'a'));
    server_send_1ucnm(10, "Hello world!");
    server_send_1ucnm(7, "Lorem ipsum dolor sit amet, consectetur cras amet.");
}
/* //Doesnt work with multithreaded server
TEST_CASE("registered send multiple messages") {
    server_send_1rcnm(2, "Alice", std::string(200, 'a'));
    server_send_1rcnm(10, "Bob", "Hello world!");
    server_send_1rcnm(7, "Jim", "Lorem ipsum dolor sit amet, consectetur cras amet.");
}

TEST_CASE("unregistered recieve multiple messages") {
    server_recieve_1ucnm(2, std::string(200, 'a'));
    server_recieve_1ucnm(10, "Hello world!");
    server_recieve_1ucnm(7, "Lorem ipsum dolor sit amet, consectetur cras amet.");
}

TEST_CASE("registered recieve multiple messages") {
    server_recieve_1rcnm(2, "Alice", std::string(200, 'a'));
    server_recieve_1rcnm(10, "Bob", "Hello world!");
    server_recieve_1rcnm(7, "Jim", "Lorem ipsum dolor sit amet, consectetur cras amet.");
}


TEST_CASE("Multiple clients sending and recieving (auto registered)") {
    nrclients_echo({"Alice"}, "Hello World!");
    nrclients_echo({"Alice", "Bob"}, "Hello World!");
    nrclients_echo({"Alice", "Bob", "Cyril"}, "Hello World!");

}
*/
