package progetto2.attacker.gpsrGrayHole;

import inet.routing.contract.IManetRouting;

simple GpsrGrayHole like IManetRouting
{
    parameters:
        // properties
        @display("i=block/routing");
        @class("inet::sec::GpsrGrayHole");
       
        // context parameters
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule = default("^.ipv4.routingTable");
        string networkProtocolModule = default("^.ipv4.ip");
        string outputInterface = default("wlan0");

        // GPSR parameters
        string planarizationMode @enum("", "GG", "RNG") = default("GG");
        string interfaces = default("*");
        double beaconInterval @unit(s) = default(10s);
        double maxJitter @unit(s) = default(0.5 * beaconInterval);
        double neighborValidityInterval @unit(s) = default(4.5 * beaconInterval);
        int positionByteLength @unit(B) = default(2 * 4B);

        // visualization parameters
        bool displayBubbles = default(false);	// display bubble messages about changes in routing state for packets
    gates:
        input ipIn;
        output ipOut;
}


