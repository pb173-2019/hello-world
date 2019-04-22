#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <QThread>
namespace helloworld {
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
