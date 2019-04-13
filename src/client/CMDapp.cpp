#include "CMDapp.h"

using namespace helloworld;

const char *CMDApp::Authors[3] = {
        "Jiří Horák",
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
            loggedIn = false;
            os << "You've been disconnected from server\n";
            os << "try help if you dont know what to do\n";
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
            } catch (Error& e) {
                if (getOption("Coludn't load user keys."
                              "Do you want to create new keys?", {'y', 'n'}) == 1)
                    return;

                _generateKeypair(password);
                client =
                        std::make_unique<Client>(username, username + "_priv.pem",
                                                 password);
            }
            client->setTransmissionManager(std::make_unique<ClientSocket>(client.get(), username));
            os << "hint: Try \"help\"\n";
            _running = true;
            std::fill(password.begin(), password.end(), 0);
            _loop();
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
                clientSocket->init();
            }
        }

        void CMDApp::login_command(CMDApp *app) {
            app->client->login();
            //TODO: Change from active waiting
            while(app->client->getId() == 0);
            app->os << "login successfull\n";
        }
        void CMDApp::logout_command(CMDApp *app) {
            app->client->logout();

            app->loggedIn = false;
        }
        void CMDApp::register_command(CMDApp *app) {
            app->client->createAccount("server_pub.pem");
            //TODO: Change from active waiting
            while(app->client->getId() == 0);
            app->os << "registration successfull\n";

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
            while (_running) {

                std::string command = getInput("");
                auto cmd = std::find_if(commands.begin(), commands.end(),
                                        [&command](const Command& c) { return c.name == command; });
                if (cmd == commands.end()) {
                    os << "Invalid command\n";
                    continue;
                }

                if (_checkStatus(cmd->required))
                    cmd->call(this);
                else
                    os << "Invalid command\n";
            }
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
                for (int i = 0; i < options.size(); ++i)
                    if (opt == options[i])
                        result = i;
                if(result == -1) {
                    os << "unrecgnized option use one of " << optionSrting.str() << '\n';
                }
            }
            return result;
        }



