//
// Copyright (C) 2013 Opensim Ltd
// Author: Levente Meszaros
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

#ifndef __INET_GpsrBlackholeNormale_H
#define __INET_GpsrBlackholeNormale_H

#include "inet/common/INETDefs.h"
#include "inet/common/geometry/common/Coord.h"
#include "inet/common/packet/Packet.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "PositionTable.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace inet {
namespace sec {

/**
 * This class implements the Greedy Perimeter Stateless Routing for Wireless Networks.
 * The implementation supports both GG and RNG planarization algorithms.
 *
 * For more information on the routing algorithm, see the GpsrBlackholeNormale paper
 * http://www.eecs.harvard.edu/~htk/publication/2000-mobi-karp-kung.pdf
 */
// TODO: optimize internal data structures for performance to use less lookups and be more prepared for routing a packet
// TODO: implement position piggybacking that is all packets should carry the position of the sender, all packets act as a beacon and reset beacon timer
// TODO: implement promiscuous mode, all receivers should process all packets with respect to neighbor positions
// KLUDGE: implement position registry protocol instead of using a global variable
class INET_API GpsrBlackholeNormale : public RoutingProtocolBase, public cListener, public NetfilterBase::HookBase
{
  private:
    // GpsrBlackholeNormale parameters
    GpsrBlackholeNormalePlanarizationMode planarizationMode = static_cast<GpsrBlackholeNormalePlanarizationMode>(-1);
    const char *interfaces = nullptr;
    simtime_t beaconInterval;
    simtime_t maxJitter;
    simtime_t neighborValidityInterval;
    bool displayBubbles;

    // context
    cModule *host = nullptr;
    IMobility *mobility = nullptr;
    IL3AddressType *addressType = nullptr;
    IInterfaceTable *interfaceTable = nullptr;
    const char *outputInterface = nullptr;
    IRoutingTable *routingTable = nullptr;    // TODO: delete when necessary functions are moved to interface table
    INetfilter *networkProtocol = nullptr;
    static PositionTable globalPositionTable;    // KLUDGE: implement position registry protocol

    // packet size
    int positionByteLength = -1;

    // internal
    cMessage *beaconTimer = nullptr;
    cMessage *purgeNeighborsTimer = nullptr;
    PositionTable neighborPositionTable;

  public:
    GpsrBlackholeNormale();
    virtual ~GpsrBlackholeNormale();

  protected:
    // module interface
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    void initialize(int stage) override;
    void handleMessageWhenUp(cMessage *message) override;

  private:
    // handling messages
    void processSelfMessage(cMessage *message);
    void processMessage(cMessage *message);

    // handling beacon timers
    void scheduleBeaconTimer();
    void processBeaconTimer();

    // handling purge neighbors timers
    void schedulePurgeNeighborsTimer();
    void processPurgeNeighborsTimer();

    // handling UDP packets
    void sendUdpPacket(Packet *packet);
    void processUdpPacket(Packet *packet);

    // handling beacons
    const Ptr<GpsrBlackholeNormaleBeacon> createBeacon();
    void sendBeacon(const Ptr<GpsrBlackholeNormaleBeacon>& beacon);
    void processBeacon(Packet *packet);

    // handling packets
    GpsrBlackholeNormaleOption *createGpsrBlackholeNormaleOption(L3Address destination);
    int computeOptionLength(GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);
    void setGpsrBlackholeNormaleOptionOnNetworkDatagram(Packet *packet, const Ptr<const NetworkHeaderBase>& networkHeader, GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);

    // returns nullptr if not found
    GpsrBlackholeNormaleOption *findGpsrBlackholeNormaleOptionInNetworkDatagramForUpdate(const Ptr<NetworkHeaderBase>& networkHeader);
    const GpsrBlackholeNormaleOption *findGpsrBlackholeNormaleOptionInNetworkDatagram(const Ptr<const NetworkHeaderBase>& networkHeader) const;

    // throws an error when not found
    GpsrBlackholeNormaleOption *getGpsrBlackholeNormaleOptionFromNetworkDatagramForUpdate(const Ptr<NetworkHeaderBase>& networkHeader);
    const GpsrBlackholeNormaleOption *getGpsrBlackholeNormaleOptionFromNetworkDatagram(const Ptr<const NetworkHeaderBase>& networkHeader) const;

    // configuration
    void configureInterfaces();

    // position
    Coord lookupPositionInGlobalRegistry(const L3Address& address) const;
    void storePositionInGlobalRegistry(const L3Address& address, const Coord& position) const;
    void storeSelfPositionInGlobalRegistry() const;
    Coord computeIntersectionInsideLineSegments(Coord& begin1, Coord& end1, Coord& begin2, Coord& end2) const;
    Coord getNeighborPosition(const L3Address& address) const;

    // angle
    double getVectorAngle(Coord vector) const;
    double getNeighborAngle(const L3Address& address) const;

    // address
    std::string getHostName() const;
    L3Address getSelfAddress() const;
    L3Address getSenderNeighborAddress(const Ptr<const NetworkHeaderBase>& networkHeader) const;

    // neighbor
    simtime_t getNextNeighborExpiration();
    void purgeNeighbors();
    std::vector<L3Address> getPlanarNeighbors() const;
    std::vector<L3Address> getPlanarNeighborsCounterClockwise(double startAngle) const;

    // next hop
    L3Address findNextHop(const L3Address& destination, GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);
    L3Address findGreedyRoutingNextHop(const L3Address& destination, GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);
    L3Address findPerimeterRoutingNextHop(const L3Address& destination, GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);

    // routing
    Result routeDatagram(Packet *datagram, GpsrBlackholeNormaleOption *GpsrBlackholeNormaleOption);

    // netfilter
    virtual Result datagramPreRoutingHook(Packet *datagram) override;
    virtual Result datagramForwardHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override;

    // lifecycle
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    // notification
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;
};
} // sec
} // namespace inet

#endif // ifndef __INET_GpsrBlackholeNormale_H

