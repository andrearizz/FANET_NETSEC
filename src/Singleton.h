

#ifndef SINGLETON_H_
#define SINGLETON_H_

#include <mutex>
#include <string>
#include <thread>
#include <iostream>
#include <list>

using namespace std;
class Singleton {

public:
    // Singleton();
    // virtual ~Singleton();
    Singleton(Singleton &other) = delete;
    void operator=(const Singleton &) = delete;
    static Singleton *GetInstance();
    void prova(string ip);
    list<string> l;


private:
    static Singleton * pinstance_;
    static std::mutex mutex_;


protected:
    Singleton();
    ~Singleton();
};

#endif /* SINGLETON_H_ */
