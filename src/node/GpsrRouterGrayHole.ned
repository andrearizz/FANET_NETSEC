package progetto2.node;

import inet.node.inet.AdhocHost;
import progetto2.attacker.gpsrGrayHole.GpsrGrayHole;

module GpsrRouterGrayHole extends AdhocHost
{
    submodules:
        gpsr: GpsrGrayHole {
            parameters:
                @display("p=825,226");
        }
    connections:
        gpsr.ipOut --> tn.in++;
        gpsr.ipIn <-- tn.out++;
}