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

#include <algorithm>

#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "inet/common/INETUtils.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/IpProtocolId_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "GpsrSecureSybil.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/queue.h"
#include "cryptopp/base64.h"
#include <chrono>
#include <cryptopp/eccrypto.h>
#include <cryptopp/asn.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/oids.h>
#include <cryptopp/dsa.h>
using namespace CryptoPP;
using namespace std;
using namespace std::chrono;


#ifdef WITH_IPv4
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#endif

#ifdef WITH_IPv6
#include "inet/networklayer/ipv6/Ipv6ExtensionHeaders_m.h"
#include "inet/networklayer/ipv6/Ipv6InterfaceData.h"
#endif

#ifdef WITH_NEXTHOP
#include "inet/networklayer/nexthop/NextHopForwardingHeader_m.h"
#endif

namespace inet {
namespace sec {


Define_Module(GpsrSecureSybil);

static inline double determinant(double a1, double a2, double b1, double b2)
{
    return a1 * b2 - a2 * b1;
}

GpsrSecureSybil::GpsrSecureSybil()
{
}

GpsrSecureSybil::~GpsrSecureSybil()
{
    cancelAndDelete(beaconTimer);
    cancelAndDelete(purgeNeighborsTimer);
}

//
// module interface
//



void GpsrSecureSybil::initialize(int stage)
{
    //EV_INFO << "KEY: " + privateKey << endl;
    if (stage == INITSTAGE_ROUTING_PROTOCOLS)
        addressType = getSelfAddress().getAddressType();

    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // GpsrSecureSybil parameters
        const char *planarizationModeString = par("planarizationMode");
        if (!strcmp(planarizationModeString, ""))
            planarizationMode = GPSR_NO_PLANARIZATION;
        else if (!strcmp(planarizationModeString, "GG"))
            planarizationMode = GPSR_GG_PLANARIZATION;
        else if (!strcmp(planarizationModeString, "RNG"))
            planarizationMode = GPSR_RNG_PLANARIZATION;
        else
            throw cRuntimeError("Unknown planarization mode");
        interfaces = par("interfaces");
        beaconInterval = par("beaconInterval");
        maxJitter = par("maxJitter");
        neighborValidityInterval = par("neighborValidityInterval");
        displayBubbles = par("displayBubbles");
        // context
        host = getContainingNode(this);
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        outputInterface = par("outputInterface");
        mobility = check_and_cast<IMobility *>(host->getSubmodule("mobility"));
        routingTable = getModuleFromPar<IRoutingTable>(par("routingTableModule"), this);
        networkProtocol = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);
        // internal
        beaconTimer = new cMessage("BeaconTimer");
        purgeNeighborsTimer = new cMessage("PurgeNeighborsTimer");
        // packet size
        positionByteLength = par("positionByteLength");
        // KLUDGE: implement position registry protocol
        globalPositionTable.clear();
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        registerService(Protocol::manet, nullptr, gate("ipIn"));
        registerProtocol(Protocol::manet, gate("ipOut"), nullptr);
        host->subscribe(linkBrokenSignal, this);
        networkProtocol->registerHook(0, this);
        WATCH(neighborPositionTable);
    }

    // generatePrivateKey(privateKey);
    // generatePublicKey(privateKey);


    AutoSeededRandomPool rng;

    ECDSA<ECP, SHA256>::PrivateKey privkey;
    ECDSA<ECP, SHA256>::PublicKey publkey;
    privkey.Initialize(rng, ASN1::secp256k1());
    /*
    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 2048);
    */

    string prvKey = "privateKeyECDSA/" + getSelfAddress().toIpv4().str();
    const char* ipPrivate = prvKey.c_str();
    Base64Encoder privkeysink(new FileSink(ipPrivate));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    /*
    RSAFunction pubkey(privkey);

    string pubKey = "publicKey/" + getSelfAddress().toIpv4().str();
    const char* ipPublic = pubKey.c_str();
    Base64Encoder pubkeysink(new FileSink(ipPublic));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();
    */

    // generateECSAPrivKey(rng);

    privkey.MakePublicKey( publkey );
    string publKey = "publicKeyECDSA/" + getSelfAddress().toIpv4().str();
    const char* ipPublic = publKey.c_str();
    Base64Encoder publkeysink(new FileSink(ipPublic));
    publkey.DEREncode(publkeysink);
    publkeysink.MessageEnd();
}
/*
void generateRSAKeys(AutoSeededRandomPool rng) {

    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 2048);

    string prvKey = "privateKey/" + getSelfAddress().toIpv4().str();
    const char* ipPrivate = prvKey.c_str();
    Base64Encoder privkeysink(new FileSink(ipPrivate));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    RSAFunction pubkey(privkey);

    string pubKey = "publicKey/" + getSelfAddress().toIpv4().str();
    const char* ipPublic = pubKey.c_str();
    Base64Encoder pubkeysink(new FileSink(ipPublic));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();
}
*/

/*
void generateECDSAPrivKey(AutoSeededRandomPool rng) {
    ECDSA<ECP, SHA256>::PrivateKey privkey;
    privkey.Initialize(rng, ASN1::secp256k1());

    string prvKey = "privateKeyECDSA/" + getSelfAddress().toIpv4().str();
    const char* ipPrivate = prvKey.c_str();
    Base64Encoder privkeysink(new FileSink(ipPrivate));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

}
*/

void GpsrSecureSybil::handleMessageWhenUp(cMessage *message)
{
    if (message->isSelfMessage())
        processSelfMessage(message);
    else
        processMessage(message);
}

//
// handling messages
//

void GpsrSecureSybil::processSelfMessage(cMessage *message)
{
    if (message == beaconTimer)
        processBeaconTimer();
    else if (message == purgeNeighborsTimer)
        processPurgeNeighborsTimer();
    else
        throw cRuntimeError("Unknown self message");
}

void GpsrSecureSybil::processMessage(cMessage *message)
{
    if (auto pk = dynamic_cast<Packet *>(message))
        processUdpPacket(pk);
    else
        throw cRuntimeError("Unknown message");
}

//
// beacon timers
//

void GpsrSecureSybil::scheduleBeaconTimer()
{
    EV_DEBUG << "Scheduling beacon timer" << endl;
    scheduleAt(simTime() + beaconInterval + uniform(-1, 1) * maxJitter, beaconTimer);
}

void GpsrSecureSybil::processBeaconTimer()
{
    EV_DEBUG << "Processing beacon timer" << endl;
    const L3Address selfAddress = getSelfAddress();
    if (!selfAddress.isUnspecified()) {
        sendBeacon(createBeaconECDSA());
        storeSelfPositionInGlobalRegistry();
    }
    scheduleBeaconTimer();
    schedulePurgeNeighborsTimer();
}

//
// handling purge neighbors timers
//

void GpsrSecureSybil::schedulePurgeNeighborsTimer()
{
    EV_DEBUG << "Scheduling purge neighbors timer" << endl;
    simtime_t nextExpiration = getNextNeighborExpiration();
    if (nextExpiration == SimTime::getMaxTime()) {
        if (purgeNeighborsTimer->isScheduled())
            cancelEvent(purgeNeighborsTimer);
    }
    else {
        if (!purgeNeighborsTimer->isScheduled())
            scheduleAt(nextExpiration, purgeNeighborsTimer);
        else {
            if (purgeNeighborsTimer->getArrivalTime() != nextExpiration) {
                cancelEvent(purgeNeighborsTimer);
                scheduleAt(nextExpiration, purgeNeighborsTimer);
            }
        }
    }
}

void GpsrSecureSybil::processPurgeNeighborsTimer()
{
    EV_DEBUG << "Processing purge neighbors timer" << endl;
    purgeNeighbors();
    schedulePurgeNeighborsTimer();
}

//
// handling UDP packets
//

void GpsrSecureSybil::sendUdpPacket(Packet *packet)
{
    //std::cout << "------------Host--------------" << endl;
    send(packet, "ipOut");
}

void GpsrSecureSybil::processUdpPacket(Packet *packet)
{
    packet->popAtFront<UdpHeader>();
    processBeacon(packet);
    schedulePurgeNeighborsTimer();
}

//
// handling beacons
//

int len;
string GpsrSecureSybil::sign(string content) {
    AutoSeededRandomPool rng;

    CryptoPP::ByteQueue bytes;

    string prvKey = "privateKey/" + getSelfAddress().toIpv4().str();
    const char* ipPrivate = prvKey.c_str();
    FileSource file(ipPrivate, true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PrivateKey privateKey;
    privateKey.Load(bytes);

    RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
    // SecByteBlock sbbSignature(privkey.SignatureLength());
    byte* signature = new byte[privkey.SignatureLength()];
    size_t length = privkey.SignMessage(rng, (const byte*) content.c_str(), content.length(), signature);

    len = length;
    string sig(reinterpret_cast<const char *>(signature), length);

    string messageBase64;

    StringSource ss(sig, true, new Base64Encoder(new StringSink(messageBase64)));

    return messageBase64;

}

string GpsrSecureSybil::signECDSA(string content) {
    AutoSeededRandomPool rng;

    CryptoPP::ByteQueue bytes;

    string prvKey = "privateKeyECDSA/" + getSelfAddress().toIpv4().str();
    const char* ipPrivate = prvKey.c_str();
    FileSource file(ipPrivate, true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();

    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    privateKey.Load(bytes);
    ECDSA<ECP, SHA256>::Signer signer(privateKey);
    signer.AccessKey().Initialize( rng, ASN1::secp256k1() );

    size_t siglen = signer.MaxSignatureLength();
    string signature(siglen, 0x00);
    // byte* signature = new byte[signer.SignatureLength()];


    siglen = signer.SignMessage( rng, (const byte*) &content[0], content.size(), (byte*) &signature[0]);
    signature.resize(siglen);

    len = siglen;
    string sig(reinterpret_cast<const char *>((byte*)&signature[0]), siglen);

    string messageBase64;

    StringSource ss(sig, true, new Base64Encoder(new StringSink(messageBase64)));


    return messageBase64;


}


const Ptr<GpsrBeaconSecure> GpsrSecureSybil::createBeacon()
{
    const auto& beacon = makeShared<GpsrBeaconSecure>();
    beacon->setAddress(getSelfAddress());
    beacon->setPosition(mobility->getCurrentPosition());
    string content = beacon -> getAddress().str() + " " + beacon -> getPosition().str();
    string signature = sign(content);
    beacon -> setSignature(signature.c_str());
    beacon->setChunkLength(B(getSelfAddress().getAddressType()->getAddressByteLength() + positionByteLength + signature.length()));
    return beacon;
}

const Ptr<GpsrBeaconSecure> GpsrSecureSybil::createBeaconECDSA() {
    const auto& beacon = makeShared<GpsrBeaconSecure>();
    beacon->setAddress(getSelfAddress());
    beacon->setPosition(mobility->getCurrentPosition());
    string content = beacon -> getAddress().str() + " " + beacon -> getPosition().str();
    cout << "Start signing" << endl;
    string signature = signECDSA(content);
    cout << "end signing" << endl;
    beacon -> setSignature(signature.c_str());
    beacon->setChunkLength(B(getSelfAddress().getAddressType()->getAddressByteLength() + positionByteLength + signature.length()));
    return beacon;
}

void GpsrSecureSybil::sendBeacon(const Ptr<GpsrBeaconSecure>& beacon)
{
    EV_INFO << "Sending beacon: address = " << beacon->getAddress() << ", position = " << beacon->getPosition() << endl;
    Packet *udpPacket = new Packet("GpsrBeaconSecure");
    udpPacket->insertAtBack(beacon);
    auto udpHeader = makeShared<UdpHeader>();
    udpHeader->setSourcePort(GPSR_UDP_PORT);
    udpHeader->setDestinationPort(GPSR_UDP_PORT);
    udpHeader->setCrcMode(CRC_DISABLED);
    udpPacket->insertAtFront(udpHeader);
    auto addresses = udpPacket->addTag<L3AddressReq>();
    addresses->setSrcAddress(getSelfAddress());
    addresses->setDestAddress(addressType->getLinkLocalManetRoutersMulticastAddress());
    udpPacket->addTag<HopLimitReq>()->setHopLimit(255);
    udpPacket->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
    udpPacket->addTag<DispatchProtocolReq>()->setProtocol(addressType->getNetworkProtocol());
    sendUdpPacket(udpPacket);
}


bool verify(Packet *packet){
    CryptoPP::ByteQueue bytes;

    const auto& beacon = packet->peekAtFront<GpsrBeaconSecure>();

    string ipPublic = "publicKey/" + beacon->getAddress().toIpv4().str();
    const char* pubKeyFile = ipPublic.c_str();
    FileSource file(pubKeyFile, true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PublicKey pubKey;
    pubKey.Load(bytes);


    std::string signature;
    CryptoPP::StringSource ss(beacon->getSignature(), true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signature)));



    RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

    //const char * signature = beacon->getSignature();
    string content = beacon -> getAddress().str() + " " + beacon -> getPosition().str();

    //cout << "Inizio a firmare" << endl;
    bool r = verifier.VerifyMessage((const byte*) content.c_str(),content.length(), (const byte*) signature.c_str(), len);

    return r;
}

bool verifyECDSA(Packet *packet) {
    CryptoPP::ByteQueue bytes;

    const auto& beacon = packet->peekAtFront<GpsrBeaconSecure>();

    string ipPublic = "publicKeyECDSA/" + beacon->getAddress().toIpv4().str();
    const char* pubKeyFile = ipPublic.c_str();
    FileSource file(pubKeyFile, true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    ECDSA<ECP, SHA256>::PublicKey pubKey;
    pubKey.Load(bytes);


    std::string signature;

    CryptoPP::StringSource ss(beacon->getSignature(), true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(signature)));


    ECDSA<ECP, SHA256>::Verifier verifier( pubKey );

    string content = beacon -> getAddress().str() + " " + beacon -> getPosition().str();


    bool r = verifier.VerifyMessage((const byte*) &content[0],content.size(), (const byte*) &signature[0], signature.size());

    if(r)
        cout << "Firma verificata correttamente" << endl;
    else
        cout << "Verifica Firma fallita" << endl;
    return r;
}



void GpsrSecureSybil::processBeacon(Packet *packet) {
    const auto& beacon = packet->peekAtFront<GpsrBeaconSecure>();
        //verify
        if(verifyECDSA(packet)){
            EV_INFO << "Processing beacon: address = " << beacon->getAddress() << ", position = " << beacon->getPosition() << ", signature = " << beacon -> getSignature() << endl;
            neighborPositionTable.setPosition(beacon->getAddress(), beacon->getPosition());
            EV_INFO << "Processing neighborPositionTable: address = " << neighborPositionTable << endl;

        }
        delete packet;
}


//
// handling packets
//



GpsrOption* GpsrSecureSybil::createGpsrOption(L3Address destination)
{
    GpsrOption *gpsrOption = new GpsrOption();
    gpsrOption->setRoutingMode(GPSR_GREEDY_ROUTING);
    gpsrOption->setDestinationPosition(lookupPositionInGlobalRegistry(destination));
    gpsrOption->setLength(computeOptionLength(gpsrOption));
    return gpsrOption;
}

int GpsrSecureSybil::computeOptionLength(GpsrOption *option)
{
    // routingMode
    int routingModeBytes = 1;
    // destinationPosition, perimeterRoutingStartPosition, perimeterRoutingForwardPosition
    int positionsBytes = 3 * positionByteLength;
    // currentFaceFirstSenderAddress, currentFaceFirstReceiverAddress, senderAddress
    int addressesBytes = 3 * getSelfAddress().getAddressType()->getAddressByteLength();
    // type and length
    int tlBytes = 1 + 1;

    return tlBytes + routingModeBytes + positionsBytes + addressesBytes;
}

//
// configuration
//

void GpsrSecureSybil::configureInterfaces()
{
    // join multicast groups
    cPatternMatcher interfaceMatcher(interfaces, false, true, false);
    for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
        InterfaceEntry *interfaceEntry = interfaceTable->getInterface(i);
        if (interfaceEntry->isMulticast() && interfaceMatcher.matches(interfaceEntry->getInterfaceName()))
            interfaceEntry->joinMulticastGroup(addressType->getLinkLocalManetRoutersMulticastAddress());
    }
}

//
// position
//

// KLUDGE: implement position registry protocol
PositionTable GpsrSecureSybil::globalPositionTable;

Coord GpsrSecureSybil::lookupPositionInGlobalRegistry(const L3Address& address) const
{
    // KLUDGE: implement position registry protocol
    Coord position = globalPositionTable.getPosition(address);
    EV_INFO << "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" << position << address << endl;
    return position;
}

void GpsrSecureSybil::storePositionInGlobalRegistry(const L3Address& address, const Coord& position) const
{
    // KLUDGE: implement position registry protocol
    globalPositionTable.setPosition(address, position);
}

void GpsrSecureSybil::storeSelfPositionInGlobalRegistry() const
{
    auto selfAddress = getSelfAddress();
    if (!selfAddress.isUnspecified())
        storePositionInGlobalRegistry(selfAddress, mobility->getCurrentPosition());
}

Coord GpsrSecureSybil::computeIntersectionInsideLineSegments(Coord& begin1, Coord& end1, Coord& begin2, Coord& end2) const
{
    // NOTE: we must explicitly avoid computing the intersection points inside due to double instability
    if (begin1 == begin2 || begin1 == end2 || end1 == begin2 || end1 == end2)
        return Coord::NIL;
    else {
        double x1 = begin1.x;
        double y1 = begin1.y;
        double x2 = end1.x;
        double y2 = end1.y;
        double x3 = begin2.x;
        double y3 = begin2.y;
        double x4 = end2.x;
        double y4 = end2.y;
        double a = determinant(x1, y1, x2, y2);
        double b = determinant(x3, y3, x4, y4);
        double c = determinant(x1 - x2, y1 - y2, x3 - x4, y3 - y4);
        double x = determinant(a, x1 - x2, b, x3 - x4) / c;
        double y = determinant(a, y1 - y2, b, y3 - y4) / c;
        if ((x <= x1 && x <= x2) || (x >= x1 && x >= x2) || (x <= x3 && x <= x4) || (x >= x3 && x >= x4) ||
                (y <= y1 && y <= y2) || (y >= y1 && y >= y2) || (y <= y3 && y <= y4) || (y >= y3 && y >= y4))
            return Coord::NIL;
        else
            return Coord(x, y, 0);
    }
}

Coord GpsrSecureSybil::getNeighborPosition(const L3Address& address) const
{
    return neighborPositionTable.getPosition(address);
}

//
// angle
//

double GpsrSecureSybil::getVectorAngle(Coord vector) const
{
    ASSERT(vector != Coord::ZERO);
    double angle = atan2(-vector.y, vector.x);
    if (angle < 0)
        angle += 2 * M_PI;
    return angle;
}

double GpsrSecureSybil::getNeighborAngle(const L3Address& address) const
{
    return getVectorAngle(getNeighborPosition(address) - mobility->getCurrentPosition());
}

//
// address
//

std::string GpsrSecureSybil::getHostName() const
{
    return host->getFullName();
}

L3Address GpsrSecureSybil::getSelfAddress() const
{
    //TODO choose self address based on a new 'interfaces' parameter
    L3Address ret = routingTable->getRouterIdAsGeneric();
#ifdef WITH_IPv6
    if (ret.getType() == L3Address::IPv6) {
        for (int i = 0; i < interfaceTable->getNumInterfaces(); i++) {
            InterfaceEntry *ie = interfaceTable->getInterface(i);
            if ((!ie->isLoopback())) {
                if (auto ipv6Data = ie->findProtocolData<Ipv6InterfaceData>()) {
                    ret = ipv6Data->getPreferredAddress();
                    break;
                }
            }
        }
    }
#endif
    return ret;
}

L3Address GpsrSecureSybil::getSenderNeighborAddress(const Ptr<const NetworkHeaderBase>& networkHeader) const
{
    const GpsrOption *gpsrOption = getGpsrOptionFromNetworkDatagram(networkHeader);
    return gpsrOption->getSenderAddress();
}

//
// neighbor
//

simtime_t GpsrSecureSybil::getNextNeighborExpiration()
{
    simtime_t oldestPosition = neighborPositionTable.getOldestPosition();
    if (oldestPosition == SimTime::getMaxTime())
        return oldestPosition;
    else
        return oldestPosition + neighborValidityInterval;
}

void GpsrSecureSybil::purgeNeighbors()
{
    neighborPositionTable.removeOldPositions(simTime() - neighborValidityInterval);
}

std::vector<L3Address> GpsrSecureSybil::getPlanarNeighbors() const
{
    std::vector<L3Address> planarNeighbors;
    std::vector<L3Address> neighborAddresses = neighborPositionTable.getAddresses();
    Coord selfPosition = mobility->getCurrentPosition();
    for (auto it = neighborAddresses.begin(); it != neighborAddresses.end(); it++) {
        auto neighborAddress = *it;
        Coord neighborPosition = neighborPositionTable.getPosition(neighborAddress);
        if (planarizationMode == GPSR_NO_PLANARIZATION)
            return neighborAddresses;
        else if (planarizationMode == GPSR_RNG_PLANARIZATION) {
            double neighborDistance = (neighborPosition - selfPosition).length();
            for (auto & witnessAddress : neighborAddresses) {
                Coord witnessPosition = neighborPositionTable.getPosition(witnessAddress);
                double witnessDistance = (witnessPosition - selfPosition).length();
                double neighborWitnessDistance = (witnessPosition - neighborPosition).length();
                if (neighborAddress == witnessAddress)
                    continue;
                else if (neighborDistance > std::max(witnessDistance, neighborWitnessDistance))
                    goto eliminate;
            }
        }
        else if (planarizationMode == GPSR_GG_PLANARIZATION) {
            Coord middlePosition = (selfPosition + neighborPosition) / 2;
            double neighborDistance = (neighborPosition - middlePosition).length();
            for (auto & witnessAddress : neighborAddresses) {
                Coord witnessPosition = neighborPositionTable.getPosition(witnessAddress);
                double witnessDistance = (witnessPosition - middlePosition).length();
                if (neighborAddress == witnessAddress)
                    continue;
                else if (witnessDistance < neighborDistance)
                    goto eliminate;
            }
        }
        else
            throw cRuntimeError("Unknown planarization mode");
        planarNeighbors.push_back(*it);
        eliminate:;
    }
    return planarNeighbors;
}

std::vector<L3Address> GpsrSecureSybil::getPlanarNeighborsCounterClockwise(double startAngle) const
{
    std::vector<L3Address> neighborAddresses = getPlanarNeighbors();
    std::sort(neighborAddresses.begin(), neighborAddresses.end(), [&](const L3Address& address1, const L3Address& address2) {
        // NOTE: make sure the neighbor at startAngle goes to the end
        auto angle1 = getNeighborAngle(address1) - startAngle;
        auto angle2 = getNeighborAngle(address2) - startAngle;
        if (angle1 <= 0)
            angle1 += 2 * M_PI;
        if (angle2 <= 0)
            angle2 += 2 * M_PI;
        return angle1 < angle2;
    });
    return neighborAddresses;
}

//
// next hop
//

L3Address GpsrSecureSybil::findNextHop(const L3Address& destination, GpsrOption *gpsrOption)
{
    switch (gpsrOption->getRoutingMode()) {
    case GPSR_GREEDY_ROUTING: return findGreedyRoutingNextHop(destination, gpsrOption);
    case GPSR_PERIMETER_ROUTING: return findPerimeterRoutingNextHop(destination, gpsrOption);
    default: throw cRuntimeError("Unknown routing mode");
    }
}

L3Address GpsrSecureSybil::findGreedyRoutingNextHop(const L3Address& destination, GpsrOption *gpsrOption)
{
    EV_DEBUG << "Finding next hop using greedy routing: destination = " << destination << endl;
    L3Address selfAddress = getSelfAddress();
    Coord selfPosition = mobility->getCurrentPosition();
    Coord destinationPosition = gpsrOption->getDestinationPosition();
    double bestDistance = (destinationPosition - selfPosition).length();
    L3Address bestNeighbor;
    std::vector<L3Address> neighborAddresses = neighborPositionTable.getAddresses();
    for (auto& neighborAddress: neighborAddresses) {
        Coord neighborPosition = neighborPositionTable.getPosition(neighborAddress);
        double neighborDistance = (destinationPosition - neighborPosition).length();
        if (neighborDistance < bestDistance) {
            bestDistance = neighborDistance;
            bestNeighbor = neighborAddress;
        }
    }
    if (bestNeighbor.isUnspecified()) {
        EV_DEBUG << "Switching to perimeter routing: destination = " << destination << endl;
        if (displayBubbles && hasGUI())
            getContainingNode(host)->bubble("Switching to perimeter routing");
        gpsrOption->setRoutingMode(GPSR_PERIMETER_ROUTING);
        gpsrOption->setPerimeterRoutingStartPosition(selfPosition);
        gpsrOption->setPerimeterRoutingForwardPosition(selfPosition);
        gpsrOption->setCurrentFaceFirstSenderAddress(selfAddress);
        gpsrOption->setCurrentFaceFirstReceiverAddress(L3Address());
        return findPerimeterRoutingNextHop(destination, gpsrOption);
    }
    else
        return bestNeighbor;
}

L3Address GpsrSecureSybil::findPerimeterRoutingNextHop(const L3Address& destination, GpsrOption *gpsrOption)
{
    EV_DEBUG << "Finding next hop using perimeter routing: destination = " << destination << endl;
    L3Address selfAddress = getSelfAddress();
    Coord selfPosition = mobility->getCurrentPosition();
    Coord perimeterRoutingStartPosition = gpsrOption->getPerimeterRoutingStartPosition();
    Coord destinationPosition = gpsrOption->getDestinationPosition();
    double selfDistance = (destinationPosition - selfPosition).length();
    double perimeterRoutingStartDistance = (destinationPosition - perimeterRoutingStartPosition).length();
    if (selfDistance < perimeterRoutingStartDistance) {
        EV_DEBUG << "Switching to greedy routing: destination = " << destination << endl;
        if (displayBubbles && hasGUI())
            getContainingNode(host)->bubble("Switching to greedy routing");
        gpsrOption->setRoutingMode(GPSR_GREEDY_ROUTING);
        gpsrOption->setPerimeterRoutingStartPosition(Coord());
        gpsrOption->setPerimeterRoutingForwardPosition(Coord());
        gpsrOption->setCurrentFaceFirstSenderAddress(L3Address());
        gpsrOption->setCurrentFaceFirstReceiverAddress(L3Address());
        return findGreedyRoutingNextHop(destination, gpsrOption);
    }
    else {
        const L3Address& firstSenderAddress = gpsrOption->getCurrentFaceFirstSenderAddress();
        const L3Address& firstReceiverAddress = gpsrOption->getCurrentFaceFirstReceiverAddress();
        auto senderNeighborAddress = gpsrOption->getSenderAddress();
        auto neighborAngle = senderNeighborAddress.isUnspecified() ? getVectorAngle(destinationPosition - mobility->getCurrentPosition()) : getNeighborAngle(senderNeighborAddress);
        L3Address selectedNeighborAddress;
        std::vector<L3Address> neighborAddresses = getPlanarNeighborsCounterClockwise(neighborAngle);
        for (auto& neighborAddress : neighborAddresses) {
            Coord neighborPosition = getNeighborPosition(neighborAddress);
            Coord intersection = computeIntersectionInsideLineSegments(perimeterRoutingStartPosition, destinationPosition, selfPosition, neighborPosition);
            if (std::isnan(intersection.x)) {
                selectedNeighborAddress = neighborAddress;
                break;
            }
            else {
                EV_DEBUG << "Edge to next hop intersects: intersection = " << intersection << ", nextNeighbor = " << selectedNeighborAddress << ", firstSender = " << firstSenderAddress << ", firstReceiver = " << firstReceiverAddress << ", destination = " << destination << endl;
                gpsrOption->setCurrentFaceFirstSenderAddress(selfAddress);
                gpsrOption->setCurrentFaceFirstReceiverAddress(L3Address());
                gpsrOption->setPerimeterRoutingForwardPosition(intersection);
            }
        }
        if (selectedNeighborAddress.isUnspecified()) {
            EV_DEBUG << "No suitable planar graph neighbor found in perimeter routing: firstSender = " << firstSenderAddress << ", firstReceiver = " << firstReceiverAddress << ", destination = " << destination << endl;
            return L3Address();
        }
        else if (firstSenderAddress == selfAddress && firstReceiverAddress == selectedNeighborAddress) {
            EV_DEBUG << "End of perimeter reached: firstSender = " << firstSenderAddress << ", firstReceiver = " << firstReceiverAddress << ", destination = " << destination << endl;
            if (displayBubbles && hasGUI())
                getContainingNode(host)->bubble("End of perimeter reached");
            return L3Address();
        }
        else {
            if (gpsrOption->getCurrentFaceFirstReceiverAddress().isUnspecified())
                gpsrOption->setCurrentFaceFirstReceiverAddress(selectedNeighborAddress);
            return selectedNeighborAddress;
        }
    }
}

//
// routing
//

INetfilter::IHook::Result GpsrSecureSybil::routeDatagram(Packet *datagram, GpsrOption *gpsrOption)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& source = networkHeader->getSourceAddress();
    const L3Address& destination = networkHeader->getDestinationAddress();
    EV_INFO << "Finding next hop: source = " << source << ", destination = " << destination << endl;
    auto nextHop = findNextHop(destination, gpsrOption);
    datagram->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(nextHop);
    if (nextHop.isUnspecified()) {
        EV_WARN << "No next hop found, dropping packet: source = " << source << ", destination = " << destination << endl;
        if (displayBubbles && hasGUI())
            getContainingNode(host)->bubble("No next hop found, dropping packet");
        return DROP;
    }
    else {
        EV_INFO << "Next hop found: source = " << source << ", destination = " << destination << ", nextHop: " << nextHop << endl;
        gpsrOption->setSenderAddress(getSelfAddress());
        auto interfaceEntry = CHK(interfaceTable->findInterfaceByName(outputInterface));
        datagram->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interfaceEntry->getInterfaceId());
        return ACCEPT;
    }
}

void GpsrSecureSybil::setGpsrOptionOnNetworkDatagram(Packet *packet, const Ptr<const NetworkHeaderBase>& networkHeader, GpsrOption *gpsrOption)
{
    packet->trimFront();
#ifdef WITH_IPv4
    if (dynamicPtrCast<const Ipv4Header>(networkHeader)) {
        auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
        gpsrOption->setType(IPOPTION_TLV_GPSR);
        B oldHlen = ipv4Header->calculateHeaderByteLength();
        ASSERT(ipv4Header->getHeaderLength() == oldHlen);
        ipv4Header->addOption(gpsrOption);
        B newHlen = ipv4Header->calculateHeaderByteLength();
        ipv4Header->setHeaderLength(newHlen);
        ipv4Header->addChunkLength(newHlen - oldHlen);
        ipv4Header->setTotalLengthField(ipv4Header->getTotalLengthField() + newHlen - oldHlen);
        insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);
    }
    else
#endif
#ifdef WITH_IPv6
        if (dynamicPtrCast<const Ipv6Header>(networkHeader)) {
            auto ipv6Header = removeNetworkProtocolHeader<Ipv6Header>(packet);
            gpsrOption->setType(IPv6TLVOPTION_TLV_GPSR);
            B oldHlen = ipv6Header->calculateHeaderByteLength();
            Ipv6HopByHopOptionsHeader *hdr = check_and_cast_nullable<Ipv6HopByHopOptionsHeader *>(ipv6Header->findExtensionHeaderByTypeForUpdate(IP_PROT_IPv6EXT_HOP));
            if (hdr == nullptr) {
                hdr = new Ipv6HopByHopOptionsHeader();
                hdr->setByteLength(B(8));
                ipv6Header->addExtensionHeader(hdr);
            }
            hdr->getTlvOptionsForUpdate().appendTlvOption(gpsrOption);
            hdr->setByteLength(B(utils::roundUp(2 + B(hdr->getTlvOptions().getLength()).get(), 8)));
            B newHlen = ipv6Header->calculateHeaderByteLength();
            ipv6Header->addChunkLength(newHlen - oldHlen);
            insertNetworkProtocolHeader(packet, Protocol::ipv6, ipv6Header);
        }
        else
#endif
#ifdef WITH_NEXTHOP
            if (dynamicPtrCast<const NextHopForwardingHeader>(networkHeader)) {
                auto nextHopHeader = removeNetworkProtocolHeader<NextHopForwardingHeader>(packet);
                gpsrOption->setType(NEXTHOP_TLVOPTION_TLV_GPSR);
                int oldHlen = nextHopHeader->getTlvOptions().getLength();
                nextHopHeader->getTlvOptionsForUpdate().appendTlvOption(gpsrOption);
                int newHlen = nextHopHeader->getTlvOptions().getLength();
                nextHopHeader->addChunkLength(B(newHlen - oldHlen));
                insertNetworkProtocolHeader(packet, Protocol::nextHopForwarding, nextHopHeader);
            }
            else
#endif
            {
            }
}

const GpsrOption *GpsrSecureSybil::findGpsrOptionInNetworkDatagram(const Ptr<const NetworkHeaderBase>& networkHeader) const
{
    const GpsrOption *gpsrOption = nullptr;

#ifdef WITH_IPv4
    if (auto ipv4Header = dynamicPtrCast<const Ipv4Header>(networkHeader)) {
        gpsrOption = check_and_cast_nullable<const GpsrOption *>(ipv4Header->findOptionByType(IPOPTION_TLV_GPSR));
    }
    else
#endif
#ifdef WITH_IPv6
        if (auto ipv6Header = dynamicPtrCast<const Ipv6Header>(networkHeader)) {
            const Ipv6HopByHopOptionsHeader *hdr = check_and_cast_nullable<const Ipv6HopByHopOptionsHeader *>(ipv6Header->findExtensionHeaderByType(IP_PROT_IPv6EXT_HOP));
            if (hdr != nullptr) {
                int i = (hdr->getTlvOptions().findByType(IPv6TLVOPTION_TLV_GPSR));
                if (i >= 0)
                    gpsrOption = check_and_cast<const GpsrOption *>(hdr->getTlvOptions().getTlvOption(i));
            }
        }
        else
#endif
#ifdef WITH_NEXTHOP
            if (auto nextHopHeader = dynamicPtrCast<const NextHopForwardingHeader>(networkHeader)) {
                int i = (nextHopHeader->getTlvOptions().findByType(NEXTHOP_TLVOPTION_TLV_GPSR));
                if (i >= 0)
                    gpsrOption = check_and_cast<const GpsrOption *>(nextHopHeader->getTlvOptions().getTlvOption(i));
            }
            else
#endif
            {
            }
    return gpsrOption;
}

GpsrOption *GpsrSecureSybil::findGpsrOptionInNetworkDatagramForUpdate(const Ptr<NetworkHeaderBase>& networkHeader)
{
    GpsrOption *gpsrOption = nullptr;

#ifdef WITH_IPv4
    if (auto ipv4Header = dynamicPtrCast<Ipv4Header>(networkHeader)) {
        gpsrOption = check_and_cast_nullable<GpsrOption *>(ipv4Header->findMutableOptionByType(IPOPTION_TLV_GPSR));
    }
    else
#endif
#ifdef WITH_IPv6
        if (auto ipv6Header = dynamicPtrCast<Ipv6Header>(networkHeader)) {
            Ipv6HopByHopOptionsHeader *hdr = check_and_cast_nullable<Ipv6HopByHopOptionsHeader *>(ipv6Header->findExtensionHeaderByTypeForUpdate(IP_PROT_IPv6EXT_HOP));
            if (hdr != nullptr) {
                int i = (hdr->getTlvOptions().findByType(IPv6TLVOPTION_TLV_GPSR));
                if (i >= 0)
                    gpsrOption = check_and_cast<GpsrOption *>(hdr->getTlvOptionsForUpdate().getTlvOptionForUpdate(i));
            }
        }
        else
#endif
#ifdef WITH_NEXTHOP
            if (auto nextHopHeader = dynamicPtrCast<NextHopForwardingHeader>(networkHeader)) {
                int i = (nextHopHeader->getTlvOptions().findByType(NEXTHOP_TLVOPTION_TLV_GPSR));
                if (i >= 0)
                    gpsrOption = check_and_cast<GpsrOption *>(nextHopHeader->getTlvOptionsForUpdate().getTlvOptionForUpdate(i));
            }
            else
#endif
            {
            }
    return gpsrOption;
}

const GpsrOption *GpsrSecureSybil::getGpsrOptionFromNetworkDatagram(const Ptr<const NetworkHeaderBase>& networkHeader) const
{
    const GpsrOption *gpsrOption = findGpsrOptionInNetworkDatagram(networkHeader);
    if (gpsrOption == nullptr)
        throw cRuntimeError("GpsrSecureSybil option not found in datagram!");
    return gpsrOption;
}

GpsrOption *GpsrSecureSybil::getGpsrOptionFromNetworkDatagramForUpdate(const Ptr<NetworkHeaderBase>& networkHeader)
{
    GpsrOption *gpsrOption = findGpsrOptionInNetworkDatagramForUpdate(networkHeader);
    if (gpsrOption == nullptr)
        throw cRuntimeError("GpsrSecureSybil option not found in datagram!");
    return gpsrOption;
}

//
// netfilter
//

INetfilter::IHook::Result GpsrSecureSybil::datagramPreRoutingHook(Packet *datagram)
{
    Enter_Method("datagramPreRoutingHook");
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& destination = networkHeader->getDestinationAddress();
    if (destination.isMulticast() || destination.isBroadcast() || routingTable->isLocalAddress(destination))
        return ACCEPT;
    else {
        // KLUDGE: this allows overwriting the GPSR option inside
        auto gpsrOption = const_cast<GpsrOption *>(getGpsrOptionFromNetworkDatagram(networkHeader));
        return routeDatagram(datagram, gpsrOption);
    }
}

INetfilter::IHook::Result GpsrSecureSybil::datagramLocalOutHook(Packet *packet)
{
    Enter_Method("datagramLocalOutHook");
    const auto& networkHeader = getNetworkProtocolHeader(packet);
    const L3Address& destination = networkHeader->getDestinationAddress();
    if (destination.isMulticast() || destination.isBroadcast() || routingTable->isLocalAddress(destination))
        return ACCEPT;
    else {
        GpsrOption *gpsrOption = createGpsrOption(networkHeader->getDestinationAddress());
        setGpsrOptionOnNetworkDatagram(packet, networkHeader, gpsrOption);
        return routeDatagram(packet, gpsrOption);
    }
}

//
// lifecycle
//

void GpsrSecureSybil::handleStartOperation(LifecycleOperation *operation)
{
    configureInterfaces();
    storeSelfPositionInGlobalRegistry();
    scheduleBeaconTimer();
}

void GpsrSecureSybil::handleStopOperation(LifecycleOperation *operation)
{
    // TODO: send a beacon to remove ourself from peers neighbor position table
    neighborPositionTable.clear();
    cancelEvent(beaconTimer);
    cancelEvent(purgeNeighborsTimer);
}

void GpsrSecureSybil::handleCrashOperation(LifecycleOperation *operation)
{
    neighborPositionTable.clear();
    cancelEvent(beaconTimer);
    cancelEvent(purgeNeighborsTimer);
}

//
// notification
//

void GpsrSecureSybil::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method("receiveChangeNotification");
    if (signalID == linkBrokenSignal) {
        EV_WARN << "Received link break" << endl;
        // TODO: remove the neighbor
    }
}
} //sec
} // namespace inet
