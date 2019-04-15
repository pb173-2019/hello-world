
#include <iostream>
#include "../shared/rsa_2048.h"
#include "transmission_net_client.h"
#include "CMDapp.h"
using namespace helloworld;

const char *CMDApp::Authors[3] = {
    "Jiri Horak",
    "Adam Ivora",
    "Ivan Mitruk"
};

void CMDApp::Command::print(std::ostream& os) const {
    os << name << std::string(15 - std::string(name).size(), ' ');
    os << info;
}

CMDApp::CMDApp(std::istream &is, std::ostream &os, QObject *parent)
    : QObject(parent), is(is), os(os) {
}

std::string CMDApp::_welcomeMessage() const {
    std::stringstream out;
    std::stringstream msg;
    msg << "Welcome to " << ApplicationName << " v" << MajorVersion
        << "." << MinorVersion;
    out << "/*" << std::string(line_length - 4, '*') << "*/\n"
        << "*" << std::string(line_length - 2, ' ') << "*\n"
        << "*" << std::string((line_length - 2 - msg.str().size())/2, ' ')
        << msg.str()
        << std::string((line_length - 2 - msg.str().size())/2, ' ') << "*\n"
        << "*" << std::string(line_length - 2, ' ') << "*\n"
        << "/*" << std::string(line_length - 4, '*') << "*/\n";
    return out.str();
}


void CMDApp::disconnected() {
    if (_connected) {
        _pause = false;
        _connected = false;
        loggedIn = false;
        client->getUsers().clear();
        os << "You've been disconnected from server\n";
        os << "try help if you dont know what to do\n";
    }
};
void CMDApp::init() {
    os << _welcomeMessage();

    username = getInput("Username");
    // TODO: find sefer way to get password
    std::string password = getInput("Password");
    try {
        client =
                std::make_unique<Client>(username, username + "_priv.pem",
                                         password);
    } catch (Error& /*e*/) {
        if (getOption("Coludn't load user keys.\n"
                      "Do you want to create new keys?", {'y', 'n'}) == 1) {
            emit close();
            return;
        }

        _generateKeypair(password);
        client =
                std::make_unique<Client>(username, username + "_priv.pem",
                                         password);
    }
    client->setTransmissionManager(std::make_unique<ClientSocket>(client.get(), username));
    os << "hint: Try \"help\"\n";
    _running = true;
    std::fill(password.begin(), password.end(), 0);
    _init = true;
};

std::string CMDApp::_versionInfo() const {
    std::stringstream out;
    out << ApplicationName << " v" << MajorVersion << "." << MinorVersion
        << "\nAuthors: ";
    auto _begin = std::begin(Authors);
    auto _end = std::end(Authors);
    for (; _begin != _end;) {
        out <<  *_begin;
        if (++_begin != _end)
            out << ", ";
    }
    return out.str();
}

void CMDApp::help_command(CMDApp *app) {

    app->os << app->_versionInfo() << '\n';
    for (auto & i: app->commands) {
        if (!app->_checkStatus(i.required))
            continue;
        app->os << '\t';
        i.print(app->os);
        app->os << '\n';
    }

}

void CMDApp::quit_command(CMDApp *app) {
    if (app->getOption("Do you really wanna quit?", {'y', 'n'}) == 0)
        app->_running = false;
}

void CMDApp::unimplemented_command(CMDApp *app) {
    app->os << "Sorry! this command is not availible yet\n";
}

void CMDApp::connect_command(CMDApp *app) {
    auto clientSocket = dynamic_cast<ClientSocket *>(app->client->getTransmisionManger());
    if (clientSocket != nullptr) {
        std::string ipAddress = app->getInput("IP address");
        clientSocket->setHostAddress(ipAddress);

        QObject::connect(clientSocket, SIGNAL(disconnected()), app, SLOT(disconnected()));
        QObject::connect(clientSocket, SIGNAL(sent()), app, SLOT(event()));
        QObject::connect(clientSocket, SIGNAL(received()), app, SLOT(onRecieve()));
        QObject::connect(clientSocket, SIGNAL(received()), app, SLOT(event()));


        clientSocket->init();
    }
    app->_connected = true;
    auto opt = app->getOption("Do you already have account on this server ?", {'y', 'n'});
    if ( opt == 0 ) {
        login_command(app);
    } else {
        register_command(app);
    }
}
void CMDApp::online_command(CMDApp *app) {
    app->client->getUsers().clear();
    app->client->sendGetOnline();
    app->_pause = true;
}
void CMDApp::login_command(CMDApp *app) {
    app->client->login();
    app->_pause = true;
}
void CMDApp::logout_command(CMDApp *app) {
    app->client->logout();
    app->loggedIn = false;
    disconnect_command(app);
}
void CMDApp::register_command(CMDApp *app) {
    app->client->createAccount(app->client->name() + "_pub.pem");
    app->_pause = true;

}
void CMDApp::disconnect_command(CMDApp *app) {
    auto clientSocket = dynamic_cast<ClientSocket *>(app->client->getTransmisionManger());
    if (clientSocket != nullptr) {
        clientSocket->closeConnection();
        app->loggedIn = false;
    } else  {
        app->os << "Cannot be disconnected\n";
    }
}


void CMDApp::find_command(CMDApp *app) {
    std::string query = app->getInput("Query");
    app->client->sendFindUsers(query);
    app->_pause = true;
}
void CMDApp::send_command(CMDApp *app) {
    std::string sid = app->getInput("ID");
    std::stringstream helper{sid};
    int id = -1;
    helper >> id;
    if (helper.fail() || id < 0) {
        app->os << "Invalid ID\n";
        return;
    }
    std::string msg = app->getInput("Message");
    std::vector<unsigned char> data(msg.begin(), msg.end());
    app->client->sendData(id, data);
    app->_skip = 1;
    app->_pause = true;

}

void CMDApp::messages_command(CMDApp *app) {
    app->client->checkForMessages();
}

bool CMDApp::_checkStatus(Command::Status required) {
    switch (required) {
    case Command::Status::None:
        return true;
    case Command::Status::Disconnected:
        return !client->getTransmisionManger() ||
                client->getTransmisionManger()->status()
                ==
                UserTransmissionManager::Status::NEED_INIT;
    case Command::Status::Connected:
        return client->getTransmisionManger() &&
                client->getTransmisionManger()->status()
                ==
                UserTransmissionManager::Status::OK;

    case Command::Status::LoggedOut:
        return !loggedIn && _checkStatus(Command::Status::Connected);
    case Command::Status::LoggedIn:
        return loggedIn;
    }
    return false;
}

void CMDApp::_loop() {
        if (_pause)
            return;
        if (!_init)
        {
            init();
        }

        std::string command = getInput("");
        auto cmd = std::find_if(commands.begin(), commands.end(),
                                [&command](const Command& c) { return c.name == command; });
        if (cmd == commands.end()) {
            os << "Invalid command\n";
            return;
        }

        if (_checkStatus(cmd->required))
            cmd->call(this);
        else
            os << "Invalid command\n";

    if (!_running)
        emit close();
};


void CMDApp::_generateKeypair(const std::string &password) {
    RSAKeyGen keygen;
    keygen.savePrivateKeyPassword(username + "_priv.pem", password);
    keygen.savePublicKey(username + "_pub.pem");
}


std::string CMDApp::getInput(const std::string &prompt) {
    os << prompt << ": ";
    os.flush();

    std::ws(is);
    std::string data;
    std::getline(is, data);
    return data;
}

int CMDApp::getOption(std::string prompt, std::vector<char> options) {
    std::stringstream optionSrting;
    optionSrting << "[";
    auto _begin = options.begin();
    auto _end= options.end();
    while(_begin!=_end) {
        optionSrting << *_begin;
        if (++_begin != _end)
            optionSrting << "/";
    }
    optionSrting << "]";

    os << prompt <<  optionSrting.str() << ": ";
    os.flush();
    int result = -1;
    while (result == -1 && is) {
        char opt = -1;
        is >> opt;
        for (unsigned i = 0; i < options.size(); ++i)
            if (opt == options[i])
                result = static_cast<int>(i);
        if(result == -1) {
            os << "unrecgnized option use one of " << optionSrting.str() << '\n';
        }
    }
    return result;
}

void CMDApp::onRecieve() {

    auto& users = client->getUsers();
    auto& recieved = client->getMessage();
    if (!loggedIn &&
        client->getId() != 0) {
        os << "succesfull login\n";
        loggedIn = true;
        _pause = false;
    } else if (loggedIn && client->getUsers().size() != 0) {
        os << "Users:\n\tID\tNAME\n";
        for ( auto & i: users) {
            os << '\t' << i.first << "\t" << i.second << "\n";
        }
        _pause = false;
        users.clear();
    }
    if(!recieved.date.empty()) {
        os << "New message:\n";
        os << recieved.from << "(" << recieved.date.substr(0, recieved.date.size() - 1) << ") : ";
        std::copy(recieved.data.begin(), recieved.data.end(), std::ostream_iterator<unsigned char>(os));
        os << '\n';

        recieved.date = ""; // marked as read
    }

    if (_skip == 1) {
        _pause = false;
        _skip = 0;
    } else if(_skip > 0) {
        --_skip;
    }
}

void CMDApp::event() {
    // maybe later
}



