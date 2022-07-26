#include "PacketManager.h"

#include <list>
#include <vector>

using namespace std;

PacketManager::PacketManager()
{
}

PacketManager::~PacketManager() {
    send_received.clear();
}

PacketManager* PacketManager::pinstance_{nullptr};
mutex PacketManager::mutex_;



/**
 * The first time we call GetInstance we will lock the storage location
 * and then we make sure again that the variable is null and then we
 * set the value. RU:
 */
PacketManager *PacketManager::GetInstance()
{
    std::lock_guard<mutex> lock(mutex_);
    if (pinstance_ == nullptr)
    {
        pinstance_ = new PacketManager();
    }
    return pinstance_;
}

void print(std::vector<std::string> const &list)
{
    for (auto const &i: list) {
        std::cout << "IP = " << i << ", ";
    }
    cout << endl;
}


//NO
void PacketManager::insert(string ip, int i) {
    vector<double> list;
    if(ip.compare("<unspec>") == 0) {
        return;
    }
    list = send_received.at(ip);
    list[i]++;
    double inviati = list[0];
    double non_inviati = list[1];
    cout << "Inviati: " << inviati << endl;
    cout << "Non inviati: " << non_inviati << endl;
    double trustness = (inviati + 1) / (inviati+non_inviati + 1);
    list[2] = trustness;

    //cout << trustness << endl;
    send_received.insert({ip, list});
    //cout << send_received.at(ip)[2] << endl;
}

void print_map(std::unordered_map<string, vector<double>> const &m)
{
    cout << "{";
    for (auto it = m.cbegin(); it != m.cend(); ++it) {
        std::cout << (*it).first << ", ";
    }
    cout << "}" << endl;
}

double PacketManager::trustness(string ip) {

    //print_map(send_received);
    if(ip.compare("<unspec>") == 0) {
        return 1;
    }
    double inviati = send_received.at(ip)[0];
    double non_inviati = send_received.at(ip)[1];
    cout << "Inviati: " << inviati << endl;
    cout << "Non inviati: " << non_inviati << endl;
    double trustness = (double)(inviati + 1) / (double)(inviati+non_inviati + 1);
    send_received.at(ip)[2] = trustness;
    cout << "IP = " << ip << " trustness = " << send_received.at(ip)[2] << endl;
    return trustness;
}



