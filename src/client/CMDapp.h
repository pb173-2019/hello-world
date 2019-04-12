//
// Created by ivan on 10.4.19.
//

#ifndef HELLOWORLD_CMDAPP_H
#define HELLOWORLD_CMDAPP_H
#include <iostream>
#include <iomanip>
#include <QObject>
#include <QCoreApplication>
#include <QThread>
#include "../shared/rsa_2048.h"
#include "transmission_net_client.h"
#include "client.h"
namespace helloworld {

    class CMDApp : public QObject {
    Q_OBJECT
        static constexpr uint16_t default_port = 5000;
        std::istream &is;
        std::ostream &os;
        std::unique_ptr<Client> client;
        std::string username;
    public:
        CMDApp(std::istream &is, std::ostream &os, QObject *parent = nullptr)
                : QObject(parent), is(is), os(os) {
        }

    Q_SIGNALS:

        void close();

    public Q_SLOTS:

        void disconnected() {
            os << "You've been disconnected from server\n";
            printInfoMessage();
        };
        void init() {
            printInfoMessage();

            loop();
        };
    private:
        void printInfoMessage() {
            os << "Hello world v0.1\n";
            os << "*******************************\n"
               << "0 - Quit\n"
               << "1 - Generate keypair\n"
               << "2 - Connect to server\n"
               << "3 - Help\n";
            if (client && client->ready()) {
                os << "4 - Register account\n";
                os << "5 - Login\n";
                os << "6 - Disconnect";
            }
        }

        void loop() {
            while (true) {

                int choice;
                os << "> ";
                is >> choice;
                {
                    std::string tmp;
                    std::getline(is, tmp);
                }
                std::string password;
                switch (choice) {

                    case 0:
                        emit close();
                        return;
                    case 1:
                        if (username.empty())
                            username = getInput("Username: ");
                        password = getInput("Password: ");
                        generateKeypair(username, password);
                        break;
                    case 2: {
                        if (!client) {
                            if (username.empty())
                                username = getInput("Username: ");
                            password = getInput("Password: ");
                            createClient(username, password);
                        }
                        auto c = dynamic_cast<ClientSocket *>(client->getTransmisionManger());
                        if (c != nullptr) {
                            std::string ip = getInput("IP address: ");
                            c->setHostAddress(ip);
                            c->setHostPort(default_port);
                            QObject::connect(c, SIGNAL(disconnected()),
                                             this, SLOT(disconnected()));
                            c->init();
                        }
                        }
                        break;
                    case 3:
                        printInfoMessage();
                        break;
                    case 4:
                        checkConnection();
                        client->createAccount(username + "_pub.pem");
                        break;
                    case 5:
                        checkConnection();
                        client->login();
                        break;
                    case 6:
                        checkConnection();
                        if (auto c = dynamic_cast<ClientSocket *>(client->getTransmisionManger());
                                c != nullptr) {
                            c->closeConnection();
                        }
                        break;
                    default:
                        std::cout << "Invalid choice.\n";
                        break;
                }
                std::fill(password.begin(), password.end(), 0);
            }
        };

        void checkConnection() {
            if (!client || !client->ready()) {
                throw std::runtime_error("Not connected to server.");
            }
        }

        void generateKeypair(const std::string &username,
                             const std::string &password) {
            RSAKeyGen keygen;
            keygen.savePrivateKeyPassword(username + "_priv.pem", password);
            keygen.savePublicKey(username + "_pub.pem");
        }

        void createClient(const std::string &username,
                             const std::string &password) {
            client =
                    std::make_unique<Client>(username, username + "_priv.pem",
                                             password);
            client->setTransmissionManager(std::make_unique<ClientSocket>(client.get()));
        }

        std::string getInput(const std::string &prompt) {
            os << prompt;
            os.flush();
            std::string data;
            std::getline(is, data);
            return data;
        }

    };
};
#endif //HELLOWORLD_CMDAPP_H
