#include <iostream>

#include <unistd.h>
#include "../shared/rsa_2048.h"
#include "client.h"

using namespace helloworld;

std::unique_ptr<Client> client;
std::string username;

void checkConnection() {
    if (!client) {
        throw std::runtime_error("Not connected to server.");
    }
}

void generateKeypair(const std::string &username, const std::string &password) {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword(username + "_priv.pem", password);
    keygen.savePublicKey(username + "_pub.pem");
}

void connectToServer(const std::string &username, const std::string &password) {
    client =
        std::make_unique<Client>(username, username + "_priv.pem", password);
}

std::string getInput(const std::string &prompt) {
    std::cout << prompt;
    std::string data;
    std::cin >> data;
    std::cout << "\n";

    return data;
}

int main(int /* argc */, char ** /* argv */) {
    while (true) {
        std::cout << "Hello world v0.1\n";
        std::cout << "*******************************\n"
                  << "1 - Generate keypair\n"
                  << "2 - Connect to server\n";
        if (client) {
            std::cout << "3 - Register account\n";
            std::cout << "4 - Login\n";
        }

        int choice;
        std::cin >> choice;
        std::string password;
        switch (choice) {
            case 1:
                username = getInput("Username: ");
                password = getInput("Password: ");
                generateKeypair(username, password);
                break;
            case 2:
                username = getInput("Username: ");
                password = getInput("Password: ");
                connectToServer(username, password);
                break;
            case 3:
                checkConnection();
                client->createAccount(username + "_pub.pem");
                break;
            default:
                std::cout << "Invalid choice.\n";
                break;
        }
        std::fill(password.begin(), password.end(), 0);
    }
}
