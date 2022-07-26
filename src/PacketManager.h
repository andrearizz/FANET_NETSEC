

#ifndef PACKETMANAGER_H_
#define PACKETMANAGER_H_

#include <mutex>
#include <string>
#include <thread>
#include <iostream>
#include <list>
#include <vector>
#include <unordered_map>

using namespace std;
class PacketManager {

public:
    // PacketManager();
    // virtual ~PacketManager();
    PacketManager(PacketManager &other) = delete;
    void operator=(const PacketManager &) = delete;
    static PacketManager *GetInstance();

    //MAPPA <IP, #Pacchetti Inviati, #Pacchetti non Inviati>
    unordered_map<string, vector<double>> send_received;
    void insert(string ip, int i);
    double trustness(string ip);

private:
    static PacketManager * pinstance_;
    static std::mutex mutex_;


protected:
    PacketManager();
    ~PacketManager();
};

#endif /* PACKETMANAGER_H_ */
