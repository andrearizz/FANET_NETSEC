//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package progetto2.node;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.physicallayer.contract.packetlevel.IRadioMedium;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.base.PacketDropVisualizerBase;
import inet.visualizer.integrated.IntegratedVisualizer;

network Fanet
{
    parameters:
		
        @figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
		
		
		
		
        int numHosts;        


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Drone;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
}


network FanetSybil
{
    
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Drone;
        
        attacker[numAttackers]: Sybil;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
   
}

network FanetSybilNormale
{
    
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Drone;
        
        attacker[numAttackers]: SybilNormale;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
   
}




network FanetSecureSybil
{    
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);

        int numHosts;
        int numAttackers;
        

    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: SecureSybil;
        
        attacker[numAttackers]: Sybil;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
        
}

network FanetCoordinateNormale
{
    
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Drone;
        
        attacker[numAttackers]: CoordAttackerNormale;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
   
}

network FanetCoordinate
{
    
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Sybil;
        
        attacker[numAttackers]: CoordAttacker;
        
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
   
}

network FanetGrayHole
{
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: Drone;
        
        attacker[numAttackers]: GrayHole;
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
}

network FanetSecureGrayHole
{
    parameters:
		@figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,38; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=host[1].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
		
		
		@figure[sntPkText](type=indicatorText; pos=380,60; anchor=w; font=,38; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=host[0].app[0].packetSent; record=figure(count); targetFigure=sntPkText);
        
        
        int numHosts;
        int numAttackers;


    submodules:

        visualizer: IntegratedVisualizer {
            @display("p=100,50");
        }

        host[numHosts]: SecureGrayHole;
        
        attacker[numAttackers]: GrayHole;
       
        configurator: Ipv4NetworkConfigurator {
            @display("p=98,250");
        }

        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=100,147");
        }
}
