//
// Created by ivan on 12.4.19.
//
#include <QObject>
#include <QCoreApplication>

#include "catch.hpp"
#include "moc_server.h"
#include "../../src/client/transmission_net_client.h"
#include "../../src/shared/utils.h"

using namespace helloworld;

constexpr const char* localhost = "127.0.0.1";

struct TestCallback : public Callable<void, std::stringstream&&> {
    std::deque<std::string> recieved;
    int n{0}, m{INT_MAX};
    QCoreApplication *a{nullptr};
    void setApp(QCoreApplication *app) {
        a = app;
    }
    void callback(std::stringstream&& ss) override  {
        recieved.push_back(ss.str());
        if (a != nullptr) {
            if (++n >= m)
                a->quit();
        }
    };
};


void connect_clients_n(int n) {
    SECTION(std::to_string(n) + "clients connecting") {
    int argc = 1;
    char name[] = "test 1";
    char * argv[2] = {name, NULL};
    QCoreApplication a(argc, argv);


    detail::MocServer server;
    server.setMaxConnections(1);
    server.start();

    QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

    TestCallback cCallback;

    for (int i = 0; i < n; i++) {
        ClientSocket client(&cCallback, "Alice");
        client.setHostPort(5000);
        client.setHostAddress(localhost);
        client.init();
    }
    a.exec();

    CHECK(server.getConnectionCounter() == n);
    }
}

void send_client_m(std::string msg) {
    SECTION("Client sending " + msg) {
        int argc = 1;
        char name[] = "test 1";
        char * argv[2] = {name, NULL};
        QCoreApplication a(argc, argv);


        detail::MocServer server;
        server.setMessageCallback([ptr = &a](detail::Connection *, std::string) {

            ptr->quit();
        });
        server.start();

        QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

        TestCallback cCallback;

            ClientSocket client(&cCallback, "Alice");
            client.setHostPort(5000);
            client.setHostAddress(localhost);
            client.init();
            std::stringstream ss(msg);
            client.send(ss);

        a.exec();

        CHECK(server.recieved.front() == msg);
    }
}

void send_nclients_m(int n, std::string msg) {
    SECTION(std::to_string(n) + " clients sending" + msg) {
        int argc = 1;
        char name[] = "test 1";
        char * argv[2] = {name, NULL};
        QCoreApplication a(argc, argv);


        detail::MocServer server;
        server.setMessageCallback([ptr = &a, i = 0, &n](detail::Connection *, std::string)
        mutable {
            if (++i >= n)
                ptr->quit();
        });
        server.start();

        QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

        TestCallback cCallback;
        for (int i = 0; i < n; i++) {
            ClientSocket client(&cCallback, "Alice");
            client.setHostPort(5000);
            client.setHostAddress(localhost);
            client.init();
            std::stringstream ss(msg);
            client.send(ss);
        }
        a.exec();
        CHECK(server.recieved.size() == n);
        for(auto& i: server.recieved) {
            CHECK(i == msg);
        }
    }
}

void client_send_nm(int n, std::string msg) {
    SECTION("client sending "+ std::to_string(n) + "x" + msg) {
        int argc = 1;
        char name[] = "test 1";
        char * argv[2] = {name, NULL};
        QCoreApplication a(argc, argv);


        detail::MocServer server;
        server.setMessageCallback([ptr = &a, i = 0, &n](detail::Connection *, std::string)
                                          mutable {
            if (++i >= n)
                ptr->quit();
        });
        server.start();

        QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

        TestCallback cCallback;

            ClientSocket client(&cCallback, "Alice");
            client.setHostPort(5000);
            client.setHostAddress(localhost);
            client.init();
        for (int i = 0; i < n; i++) {
            std::stringstream ss(msg);
            client.send(ss);
        }
        a.exec();
        CHECK(server.recieved.size() == n);
        for(auto& i: server.recieved) {
            CHECK(i == msg);
        }
    }
}


void client_recieve_nm(int n, std::string msg) {
    SECTION("Client recieving " + std::to_string(n) + "x" + msg) {
        int argc = 1;
        char name[] = "test 1";
        char * argv[2] = {name, NULL};
        QCoreApplication a(argc, argv);

        std::string result;
        detail::MocServer server;
        server.setConnectionCallback([&n, &msg](detail::MocServer *o, detail::Connection *c) {
            for (int i = 0; i < n ; i ++) {
                std::stringstream s(msg);
                c->send(std::move(s));
            }
        });

        server.start();
        QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

        TestCallback cCallback;
        cCallback.a = &a;
        cCallback.m = n;


        ClientSocket client(&cCallback, "Alice");
        client.setHostPort(5000);
        client.setHostAddress(localhost);
        client.init();

        a.exec();

        CHECK(cCallback.recieved.size() == n);
        for (auto& i : cCallback.recieved) {
            CHECK(i == msg);
        }
    }

    }

void client_recieve_m(std::string msg) {
    SECTION("Client recieving" + msg) {
        int argc = 1;
        char name[] = "test 1";
        char * argv[2] = {name, NULL};
        QCoreApplication a(argc, argv);

        std::string result;
        detail::MocServer server;
        server.setConnectionCallback([&msg](detail::MocServer *o, detail::Connection *c) {
            std::stringstream s(msg);
            c->send(std::move(s));
        });

        server.start();
        QObject::connect(&server, SIGNAL(finished()), &a, SLOT(quit()));

        TestCallback cCallback;
        cCallback.a = &a;
        cCallback.m = 1;


            ClientSocket client(&cCallback, "Alice");
            client.setHostPort(5000);
            client.setHostAddress(localhost);
            client.init();

        a.exec();

        CHECK(cCallback.recieved.front() == msg);
    }
}



TEST_CASE("X Clients connecting") {
    connect_clients_n(1);
    connect_clients_n(2);
    connect_clients_n(5);
}

TEST_CASE("recieving message") {
    client_recieve_m("A");
    client_recieve_m("Hello world!");
    client_recieve_m("Lorem ipsum dolor sit amet, consectetuer adipiscing elit."
                     "Curabitur vitae diam non enim vestibulum interdum. Nam se"
                     "d tellus id magna elementum tincidunt. Praesent id justo "
                     "in neque elementum ultrices. Duis risus. Etiam posuere la"
                     "cus quis dolor. Duis sapien nunc, commodo et, interdum su"
                     "scipit, sollicitudin et, dolor. Integer tempor. Mauris do"
                     "lor felis, sagittis at, luctus sed, aliquam non, tellus. "
                     "Curabitur ligula sapien, pulvinar a vestibulum quis, faci"
                     "lisis vel sapien.");
    client_recieve_m(std::string(10000, 'a'));
}

TEST_CASE("send message") {
    send_client_m("A");
    send_client_m("Hello world!");
    send_client_m("Lorem ipsum dolor sit amet, consectetuer adipiscing elit."
                     "Curabitur vitae diam non enim vestibulum interdum. Nam se"
                     "d tellus id magna elementum tincidunt. Praesent id justo "
                     "in neque elementum ultrices. Duis risus. Etiam posuere la"
                     "cus quis dolor. Duis sapien nunc, commodo et, interdum su"
                     "scipit, sollicitudin et, dolor. Integer tempor. Mauris do"
                     "lor felis, sagittis at, luctus sed, aliquam non, tellus. "
                     "Curabitur ligula sapien, pulvinar a vestibulum quis, faci"
                     "lisis vel sapien.");
    send_client_m(std::string(10000, 'a'));
}


TEST_CASE("multiple clients send message") {
    send_nclients_m(10, "O");

    send_nclients_m(10, "Hello world!");
    send_nclients_m(2, "Lorem ipsum dolor sit amet, consectetuer adipiscing elit."
                   "Curabitur vitae diam non enim vestibulum interdum. Nam se"
                   "d tellus id magna elementum tincidunt. Praesent id justo "
                   "in neque elementum ultrices. Duis risus. Etiam posuere la"
                   "cus quis dolor. Duis sapien nunc, commodo et, interdum su"
                   "scipit, sollicitudin et, dolor. Integer tempor. Mauris do"
                   "lor felis, sagittis at, luctus sed, aliquam non, tellus. "
                   "Curabitur ligula sapien, pulvinar a vestibulum quis, faci"
                   "lisis vel sapien.");
}

TEST_CASE("one client send multiple messages") {
    client_send_nm(10, "O");

    client_send_nm(10, "Hello world!");
    client_send_nm(2, "Lorem ipsum dolor sit amet, consectetuer adipiscing elit."
                       "Curabitur vitae diam non enim vestibulum interdum. Nam se"
                       "d tellus id magna elementum tincidunt. Praesent id justo "
                       "in neque elementum ultrices. Duis risus. Etiam posuere la"
                       "cus quis dolor. Duis sapien nunc, commodo et, interdum su"
                       "scipit, sollicitudin et, dolor. Integer tempor. Mauris do"
                       "lor felis, sagittis at, luctus sed, aliquam non, tellus. "
                       "Curabitur ligula sapien, pulvinar a vestibulum quis, faci"
                       "lisis vel sapien.");
}

TEST_CASE("one client recieves multiple message") {
    client_recieve_nm(10, "O");

    client_recieve_nm(10, "Hello world!");
    client_recieve_nm(2, "Lorem ipsum dolor sit amet, consectetuer adipiscing elit."
                      "Curabitur vitae diam non enim vestibulum interdum. Nam se"
                      "d tellus id magna elementum tincidunt. Praesent id justo "
                      "in neque elementum ultrices. Duis risus. Etiam posuere la"
                      "cus quis dolor. Duis sapien nunc, commodo et, interdum su"
                      "scipit, sollicitudin et, dolor. Integer tempor. Mauris do"
                      "lor felis, sagittis at, luctus sed, aliquam non, tellus. "
                      "Curabitur ligula sapien, pulvinar a vestibulum quis, faci"
                      "lisis vel sapien.");
}

TEST_CASE("Reaction to problems") {
    SECTION("connecting to wrong address") {

        TestCallback cCallback;
        detail::RequireEmitted e;

        ClientSocket client(&cCallback, "Alice");

        QObject::connect(&client, SIGNAL(disconnected()), &e, SLOT(done()));

        client.setHostPort(5000);
        client.setHostAddress("255.255.255.255");
        client.init(); // should emit disconnect right here (no QCoreApp needed)


        CHECK(e.emmited);
    }
    SECTION("Client prematurely disconnected") {
            int argc = 1;
            char name[] = "test 1";
            char * argv[2] = {name, NULL};
            QCoreApplication a(argc, argv);

            detail::RequireEmitted e;

            detail::MocServer server;
            server.setConnectionCallback([ptr = &a](detail::MocServer *s,detail::Connection *c) {
                c->closing();
            });
            server.start();

            TestCallback cCallback;

            ClientSocket client(&cCallback, "Alice");

            QObject::connect(&client, SIGNAL(disconnected()), &e, SLOT(done()));
            QObject::connect(&client, SIGNAL(disconnected()), &a, SLOT(quit()));

        client.setHostPort(5000);
            client.setHostAddress(localhost);
            client.init();


            a.exec();

            CHECK(e.emmited);

    }

}