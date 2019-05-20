#include "CMDapp.h"
#include <iostream>
#include "../shared/rsa_2048.h"
#include "transmission_net_client.h"

namespace helloworld {
constexpr int max__timeout = 5000;
const char *CMDApp::Authors[3] = {"Jiri Horak", "Adam Ivora", "Ivan Mitruk"};

void CMDApp::Command::print(ChatWindow &window) const {
    window.appendLine(name + std::string(15 - std::string(name).size(), ' ') +
                      info);
}

CMDApp::CMDApp(QObject *parent) : QObject(parent), _timeout(new QTimer(this)) {
    connect(_timeout, &QTimer::timeout, this, &CMDApp::onTimer);
    _timeout->setInterval(max__timeout);
}

std::string CMDApp::_welcomeMessage() const {
    std::stringstream out;
    std::stringstream msg;
    msg << "Welcome to " << ApplicationName << " v" << MajorVersion << "."
        << MinorVersion;
    return out.str();
}

void CMDApp::disconnected() {
    if (status >= State::Connected) {
        status = Disconnected;
        client->getUsers().clear();
        print("You've been disconnected from server");
        print("try help if you dont know what to do");
    }
}

void CMDApp::init() {
    print(_welcomeMessage());

    status = Disconnected;

    username = getInput("Username");
    // TODO: find safer way to get password

    zero::str_t password;
    while ((password = getSafeInput("Password")).size() <
           RSA2048::MIN_PASS_LEN) {
        print("Password must be at least " +
              std::to_string(RSA2048::MIN_PASS_LEN) + " characters long");
    }
    try {
        print("Trying to load keys...");
        client = std::make_unique<Client>(username, username + "_priv.pem",
                                          username + "_pub.pem", password);
    } catch (Error &e) {
        print(e.message);
        print("Generating new keys...");
        _generateKeypair(password);
        client = std::make_unique<Client>(username, username + "_priv.pem",
                                          username + "_pub.pem", password);
    }
    print("Keys loaded successfuly");
    client->setTransmissionManager(
        std::make_unique<ClientSocket>(client.get(), username));
    connect(client.get(), &Client::error, this, &CMDApp::onError);
    print("hint: Try \"help\"");
    _running = true;
    std::fill(password.begin(), password.end(), 0);
    emit poll();
}

std::string CMDApp::_versionInfo() const {
    std::stringstream out;
    out << ApplicationName << " v" << MajorVersion << "." << MinorVersion
        << "\nAuthors: ";
    auto _begin = std::begin(Authors);
    auto _end = std::end(Authors);
    for (; _begin != _end;) {
        out << *_begin;
        if (++_begin != _end) out << ", ";
    }
    return out.str();
}

void CMDApp::help_command(CMDApp *app) {
    app->print(app->_versionInfo());
    for (auto &i : app->commands) {
        if (!app->_checkStatus(i.required)) continue;
        app->print("\t");
        i.print(app->window);
        app->print("");
    }
}

void CMDApp::quit_command(CMDApp *app) {
    if (app->getOption("Do you really wanna quit?", {'y', 'n'}) == 0)
        app->_running = false;
}

void CMDApp::unimplemented_command(CMDApp *app) {
    app->print("Sorry! this command is not availible yet");
}

void CMDApp::connect_command(CMDApp *app) {
    auto clientSocket =
        dynamic_cast<ClientSocket *>(app->client->getTransmisionManger());
    if (clientSocket != nullptr) {
        std::string ipAddress = app->getInput("IP address");
        clientSocket->setHostAddress(ipAddress);

        QObject::connect(clientSocket, SIGNAL(disconnected()), app,
                         SLOT(disconnected()));
        QObject::connect(clientSocket, SIGNAL(sent()), app, SLOT(onEvent()));
        QObject::connect(clientSocket, SIGNAL(received()), app,
                         SLOT(onRecieve()));
        QObject::connect(clientSocket, SIGNAL(received()), app,
                         SLOT(onEvent()));

        app->print("Connecting...");
        clientSocket->init();
        if (clientSocket->status() == UserTransmissionManager::Status::OK)
            app->print("Connection successful");
        else {
            app->print("Connection failed");
            return;
        }
    }
    app->status = Connected;
    login_command(app);
}

void CMDApp::online_command(CMDApp *app) {
    app->client->getUsers().clear();
    app->client->sendGetOnline();
    app->_timeout->start();
}

void CMDApp::login_command(CMDApp *app) {
    app->status = LoggingIn;
    app->client->login();
    app->print("trying to login");
    app->_timeout->start();
}

void CMDApp::logout_command(CMDApp *app) {
    app->client->logout();
    app->status = Connected;
    disconnect_command(app);
}

void CMDApp::register_command(CMDApp *app) {
    app->status = Registering;
    app->client->createAccount(app->client->name() + "_pub.pem");
    app->print("trying to register");
    app->_timeout->start();
}

void CMDApp::disconnect_command(CMDApp *app) {
    auto clientSocket =
        dynamic_cast<ClientSocket *>(app->client->getTransmisionManger());
    if (clientSocket != nullptr) {
        clientSocket->closeConnection();
        app->status = Disconnected;
    } else {
        app->print("Cannot be disconnected");
    }
}

void CMDApp::find_command(CMDApp *app) {
    std::string query = app->getInput("Query");
    app->client->sendFindUsers(query);
    app->_timeout->start();
}

void CMDApp::send_command(CMDApp *app) {
    std::string sid = app->getInput("ID");
    std::stringstream helper{sid};
    int id = -1;
    helper >> id;
    if (helper.fail() || id < 0) {
        app->print("Invalid ID");
        return;
    }
    std::string msg = app->getInput("Message");
    std::vector<unsigned char> data(msg.begin(), msg.end());
    try {
        app->client->sendData(static_cast<uint32_t>(id), data);
    } catch (std::exception &error) {
        app->print(error.what());
    }
}

void CMDApp::messages_command(CMDApp *app) { app->client->checkForMessages(); }

bool CMDApp::_checkStatus(Command::Status required) {
    switch (required) {
        case Command::Status::None:
            return status > State::Uninit;
        case Command::Status::Disconnected:
            return status == State::Disconnected;
        case Command::Status::Connected:
            return status >= State::Connected;
        case Command::Status::LoggedOut:
            return status < State::LoggedIn;
        case Command::Status::LoggedIn:
            return status >= State::LoggedIn;
    }
    return false;
}

void CMDApp::_loop(QString input) {
    try {
        if (!_running) return;
        auto cmd = std::find_if(commands.begin(), commands.end(),
                                [&input](const Command &c) {
                                    return c.name == input.toStdString();
                                });

        if (cmd == commands.end()) {
            print("Invalid command");
            emit poll();
            return;
        }

        if (_checkStatus(cmd->required))
            cmd->call(this);
        else
            print("Invalid command");

        if (!_running)
            emit close();
        else
            emit poll();
    } catch (Error &error) {
        print(error.what());
    }
}

void CMDApp::_generateKeypair(const zero::str_t &password) {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword(username + "_priv.pem", password);
    keygen.savePublicKey(username + "_pub.pem");
}

std::string CMDApp::getInput(const std::string &prompt) {
    print(prompt + ": ");
    return window.getMessage();
}

zero::str_t CMDApp::getSafeInput(const std::string &prompt) {
    print(prompt + ": ");

    auto &&msg = window.getMessage();
    return {msg.begin(), msg.end()};
}

int CMDApp::getOption(std::string prompt, std::vector<char> options) {
    std::stringstream optionSrting;
    optionSrting << "[";
    auto _begin = options.begin();
    auto _end = options.end();
    while (_begin != _end) {
        optionSrting << *_begin;
        if (++_begin != _end) optionSrting << "/";
    }
    optionSrting << "]";

    print(prompt + optionSrting.str() + ": ");
    int result = -1;
    std::stringstream is{window.getMessage()};
    while (result == -1 && is) {
        char opt = -1;
        is >> opt;
        for (unsigned i = 0; i < options.size(); ++i)
            if (opt == options[i]) result = static_cast<int>(i);
        if (result == -1) {
            print("unrecgnized option use one of " + optionSrting.str());
        }
    }
    return result;
}

void CMDApp::onRecieve() {
    auto &users = client->getUsers();
    auto &recieved = client->getMessage();
    if (status < State::LoggedIn && client->getId() != 0) {
        if (status == State::Registering)
            print("registration");
        else
            print("login");
        print(" success");
        _timeout->stop();
        status = LoggedIn;
    } else if (status >= State::LoggedIn && !client->getUsers().empty()) {
        print("Users:\n\tID\tNAME");
        for (auto &i : users) {
            print("\t" + std::to_string(i.first) + "\t" + i.second);
        }

        users.clear();
        _timeout->stop();
    }
    if (!recieved.date.empty()) {
        print("New message:");
        print("\t" + recieved.from + "(" +
              recieved.date.substr(0, recieved.date.size() - 1) + ") : ");
        print({recieved.data.begin(), recieved.data.end()});

        recieved = {};    // clear
    }
}

void CMDApp::onError(QString string) {
    _timeout->stop();
    if (status == State::LoggingIn) {
        register_command(this);
    } else if (status == State::Registering) {
        print("could not authenticate to server");
        disconnect_command(this);
    } else {
        print("Error: " + string.toStdString());
    }
}

void CMDApp::onTimer() {
    if (status >= Connected) {
        print("Server timed out");
        disconnect_command(this);
    }
}

void CMDApp::onEvent() {
    // not implemented yet
}

}    // namespace helloworld
