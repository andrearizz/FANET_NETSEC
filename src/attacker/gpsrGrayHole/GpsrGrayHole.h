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

#ifndef __INET_GpsrGrayHole_H
#define __INET_GpsrGrayHole_H

#include "inet/common/INETDefs.h"
#include "inet/common/geometry/common/Coord.h"
#include "inet/common/packet/Packet.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "host/gpsr/Gpsr_m.h"
#include "host/gpsr/Gpsr.h"
#include "host/gpsr/PositionTable.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace inet {
namespace sec {


class GpsrGrayHole: public Gpsr {
public:
    GpsrGrayHole();
    virtual ~GpsrGrayHole();

};
} // sec
} // namespace inet

#endif // ifndef __INET_GpsrGrayHole_H

