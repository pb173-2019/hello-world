//
// Created by ivan on 10.4.19.
//

/*
 * JUST FOR VISUAL TESTING OF NET_CLIENT
 *
 */

#ifndef HELLOWORLD_CMDAPP_H
#define HELLOWORLD_CMDAPP_H

#include <atomic>
#include <QObject>
#include <mutex>
#include <condition_variable>
#include "client.h"

namespace helloworld {

    class CMDApp : public QObject {
    Q_OBJECT
        static constexpr uint16_t default_port = 5000;

        // 80 is default, which might not be actual length, but it's generally
        // considered as standard (won't matter when we create GUI)
        static constexpr int line_length = 80;

        static constexpr const char* ApplicationName = "Hello World!";
        static constexpr int MajorVersion = 0, MinorVersion = 1;
        static const char *Authors[3];

        std::atomic_bool _running{false};
        std::istream &is;
        std::ostream &os;
        std::unique_ptr<Client> client;
        std::string username;

        bool loggedIn{false}, _pause{false}, _init{false}, _connected{false};

        enum {nothing ,message, login, search}  waitingFor{nothing};

        struct Command {
            using CMDfunc_t = void(*)(CMDApp*);
            const char * name;
            CMDfunc_t call;
            const char *info;

            enum Status {None, Disconnected, Connected, LoggedOut,  LoggedIn} required;
            void print(std::ostream& os) const;
        };


        const std::vector<Command> commands{
            {"help", &CMDApp::help_command, "prints help message", Command::Status::None},
            {"connect", &CMDApp::connect_command, "connect to server", Command::Status::Disconnected},

            // automatic after connection
            //{"login", &CMDApp::login_command, "log in as existing user", Command::Status::LoggedOut},
            //{"register", &CMDApp::register_command, "register new user", Command::Status::LoggedOut},

            {"send", &CMDApp::send_command, "send message to user", Command::Status::LoggedIn},
            {"online", &CMDApp::online_command, "get list of online users", Command::Status::LoggedIn},
            {"find", &CMDApp::find_command, "find user", Command::Status::LoggedIn},
            {"recv", &CMDApp::messages_command, "recieve awaiting messages", Command::Status::LoggedIn},
            {"logout", &CMDApp::logout_command, "log out, but stay connected", Command::Status::LoggedIn},

            // automatic after logout
            //{"disconnect", &CMDApp::disconnect_command, "disconnect from current server", Command::Status::Connected},

            {"quit", &CMDApp::quit_command, "close this application", Command::Status::None}
        };




    public:
        CMDApp(std::istream &is, std::ostream &os, QObject *parent = nullptr);

    Q_SIGNALS:
        void close();
    public Q_SLOTS:
        /**
         * reaction to disconnect
         */
        void disconnected();
        /**
         * init application on start
         */
        void init();
        /**
         * actions trigered on receive
         */
        void onRecieve();
        /**
         * action trigered on general event (nothing yer)
         */
        void event();
        /**
         * main application loop (called repeatedly)
         */
        void _loop();
    private:
        /**
         * creats nice messagge about current version of programs
         * (name, version, authors - viz implementation)
         * @return string containing version info
         */
        std::string _versionInfo() const;

        /**
         * creates nice welcome message from app name and version
         * @return string containing welcome message
         */
        std::string _welcomeMessage() const;
        /**
         * checks whether application is in required state
         * @param required state/status
         * @return true if it is in required state, false otherwise
         */
        bool _checkStatus(Command::Status required);

        /**
         * quit_command helper (emits signal)
         */
        void _quit();

        /**
         * genereates new key pair
         * @param password password to encrypt private key
         */
        void _generateKeypair(const std::string &password);


        /*
         * static functions representing different commands
         */
        static void help_command(CMDApp *app);
        static void quit_command(CMDApp *app);
        static void unimplemented_command(CMDApp *app);
        static void connect_command(CMDApp *app) ;
        static void login_command(CMDApp *app);
        static void logout_command(CMDApp *app);
        static void register_command(CMDApp *app);
        static void disconnect_command(CMDApp *app);
        static void online_command(CMDApp *app);
        static void find_command(CMDApp *app);
        static void send_command(CMDApp *app);
        static void messages_command(CMDApp *app);
        //static void generateKeypair_command(CMDApp *app); // maybe not neccessary?


        /**
         * gets input from application input stream
         * @param prompt to display to user
         * @return users input
         */
        std::string getInput(const std::string &prompt);

        /**
         * get option from user
         * @param prompt to display to user
         * @param options from which user should choose
         * @return index of option (-1 on error)
         */
        int getOption(std::string prompt, std::vector<char> options);

    };
};
#endif //HELLOWORLD_CMDAPP_H
