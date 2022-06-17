

#ifndef SINGLETON_H_
#define SINGLETON_H_

#include <mutex>
#include <string>
#include <thread>
#include <iostream>
#include <list>
#include <vector>
#include <unordered_map>

using namespace std;
class Singleton {

public:
    // Singleton();
    // virtual ~Singleton();
    Singleton(Singleton &other) = delete;
    void operator=(const Singleton &) = delete;
    static Singleton *GetInstance();
    void prova(string ip);
    unordered_map<string, vector<double>> send_received;
    void insert(string ip, int i);
    double trustness(string ip);

private:
    static Singleton * pinstance_;
    static std::mutex mutex_;


protected:
    Singleton();
    ~Singleton();
};

#endif /* SINGLETON_H_ */
