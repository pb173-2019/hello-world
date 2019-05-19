/*
 * @file CMDApp.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief main client application
 *
 */
#ifndef HELLOWORLD_CMDAPP_H
#define HELLOWORLD_CMDAPP_H

#include <QObject>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <condition_variable>
#include "ChatWindow.h"
#include "client.h"

namespace helloworld {

/**
 * Class that performs reading from socket
 * active waiting
 */
class Worker : public QObject {
    Q_OBJECT

   public:
    ChatWindow &window;
    Worker(ChatWindow &window) : QObject(nullptr), window(window) {}

   public slots:

    void doWork() {
        std::string data;
        while (data.empty()) {
            data = window.getMessage();
        }
        emit read(QString::fromStdString(data));
    }

   signals:

    void read(QString);
};

/**
 * Thread pooling management:
 * thread container for Worker class
 */
class cinPoll : public QObject {
    Q_OBJECT
    ChatWindow &window;
    QThread *thread;

   public:
    cinPoll(ChatWindow &window, QObject *parent = nullptr)
        : QObject(parent), window(window) {}

   public slots:

    /**
     * Start the thread, QThread is deleted by QT framework
     */
    void start() {
        Worker *worker = new Worker(window);
        thread = new QThread();
        worker->moveToThread(thread);
        connect(thread, &QThread::finished, worker, &QObject::deleteLater);
        connect(thread, &QThread::started, worker, &Worker::doWork);
        connect(worker, &Worker::read, this, &cinPoll::read);
        thread->start();
    }

   signals:

    void read(QString);
};

class CMDApp : public QObject {
    Q_OBJECT
    static constexpr uint16_t default_port = 5000;

    // 80 is default, which might not be actual length, but it's generally
    // considered as standard (won't matter when we create GUI)
    static constexpr int line_length = 80;

    static constexpr const char *ApplicationName = "Hello World!";
    static constexpr int MajorVersion = 0, MinorVersion = 2;
    static const char *Authors[3];

    std::atomic_bool _running{false};
    std::unique_ptr<Client> client;
    std::string username;

    enum State {
        Uninit,
        Disconnected,
        Connected,
        LoggingIn,
        Registering,
        LoggedIn
    } status{Uninit};
    QTimer *_timeout;

    struct Command {
        using CMDfunc_t = void (*)(CMDApp *);
        const char *name;
        CMDfunc_t call;
        const char *info;

        enum Status {
            None,
            Disconnected,
            Connected,
            LoggedOut,
            LoggedIn
        } required;

        void print(ChatWindow &window) const;
    };

    const std::vector<Command> commands{
        {"help", &CMDApp::help_command, "prints help message",
         Command::Status::None},
        {"connect", &CMDApp::connect_command, "connect to server",
         Command::Status::Disconnected},

        // automatic after connection
        //{"login", &CMDApp::login_command, "log in as existing user",
        // Command::Status::LoggedOut},
        //{"register", &CMDApp::register_command, "register new user",
        // Command::Status::LoggedOut},

        {"send", &CMDApp::send_command, "send message to user",
         Command::Status::LoggedIn},
        {"online", &CMDApp::online_command, "get list of online users",
         Command::Status::LoggedIn},
        {"find", &CMDApp::find_command, "find user", Command::Status::LoggedIn},
        {"recv", &CMDApp::messages_command, "recieve awaiting messages",
         Command::Status::LoggedIn},
        {"logout", &CMDApp::logout_command, "log out, but stay connected",
         Command::Status::LoggedIn},

        // automatic after logout
        //{"disconnect", &CMDApp::disconnect_command, "disconnect from current
        // server", Command::Status::Connected},

        {"quit", &CMDApp::quit_command, "close this application",
         Command::Status::None}};

   public:
    ChatWindow window;

    CMDApp(QObject *parent = nullptr);

   Q_SIGNALS:

    void close();

    void poll();

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
    void onEvent();

    /**
     * @brief onError called after server sends error message
     */
    void onError(QString);

    /**
     * @brief onTimer called after timer runs out
     */
    void onTimer();

    /**
     * main application loop (called repeatedly)
     */
    void _loop(QString);

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
    void _generateKeypair(const zero::str_t &password);

    /*
     * static functions representing different commands
     */
    static void help_command(CMDApp *app);

    static void quit_command(CMDApp *app);

    static void unimplemented_command(CMDApp *app);

    static void connect_command(CMDApp *app);

    static void login_command(CMDApp *app);

    static void logout_command(CMDApp *app);

    static void register_command(CMDApp *app);

    static void disconnect_command(CMDApp *app);

    static void online_command(CMDApp *app);

    static void find_command(CMDApp *app);

    static void send_command(CMDApp *app);

    static void messages_command(CMDApp *app);
    // static void generateKeypair_command(CMDApp *app); // maybe not be
    // neccessary ?

    /**
     * gets input from application input stream
     * @param prompt to display to user
     * @return users input
     */
    std::string getInput(const std::string &prompt);
    zero::str_t getSafeInput(const std::string &prompt);

    /**
     * get option from user
     * @param prompt to display to user
     * @param options from which user should choose
     * @return index of option (-1 on error)
     */
    int getOption(std::string prompt, std::vector<char> options);

    void print(const std::string &message) { window.appendLine(message); }
};

}    // namespace helloworld

#endif    // HELLOWORLD_CMDAPP_H
