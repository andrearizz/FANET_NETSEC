#include "Singleton.h"
#include <list>

using namespace std;

Singleton::Singleton()
{
}

Singleton::~Singleton() {
}

Singleton* Singleton::pinstance_{nullptr};
mutex Singleton::mutex_;



/**
* The first time we call GetInstance we will lock the storage location
* and then we make sure again that the variable is null and then we
* set the value. RU:
*/
Singleton *Singleton::GetInstance()
{
std::lock_guard<mutex> lock(mutex_);
if (pinstance_ == nullptr)
{
pinstance_ = new Singleton();
}
return pinstance_;
}

void print(std::list<std::string> const &list)
{
    for (auto const &i: list) {
        std::cout << "IP = " << i << ", ";
    }
    cout << endl;
}

void Singleton::prova(string ip) {
    l.push_back(ip);
    print(l);
}




