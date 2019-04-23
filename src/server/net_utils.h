/*
 * @file net_utils.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief misc structures used with server network interface
 *
 */

#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <QThread>
namespace helloworld {

/**
 * @brief The EventThread class Qt thread with event loop
 */
class EventThread : public QThread {
    Q_OBJECT
public:
    EventThread(QObject * parent = nullptr)
        : QThread(parent) {
    }
    ~EventThread() override = default;
    public slots:
    void run() override {
        exec();
    }
};

/**
 * PtrWrap, wraps raw pointer of any type ( made so Qthreaddata doesnt delete ptr content )
 */
template <typename T>
class PtrWrap {
    T *ptr{nullptr};
public:
    PtrWrap() noexcept = default;
    PtrWrap(T *val) noexcept : ptr(val) {}
    operator T*() const {
     return ptr;
    }
};
}
#endif // NET_UTILS_H
