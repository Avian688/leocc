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

#include <inet/networklayer/ipv4/Ipv4Header_m.h>

#include "Leocc.h"
namespace inet {
namespace tcp {

Define_Module(Leocc);

Leocc::Leocc() {

}

Leocc::~Leocc() {
}

void Leocc::initialize(int stage)
{
    TcpPaced::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        reconfigurationState = false;
        minRtt = SIMTIME_ZERO;
        minRttFluctuation = SIMTIME_ZERO;
    }
}

TcpConnection* Leocc::createConnection(int socketId)
{
    auto moduleType = cModuleType::get("leocc.transportlayer.leocc.LeoccConnection");
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", socketId);
    auto module = check_and_cast<TcpConnection*>(moduleType->createScheduleInit(submoduleName, this));
    module->initConnection(this, socketId);
    return module;
}

void Leocc::setReconfigurationState(bool reconfiguration)
{
    reconfigurationState = reconfiguration;
}

bool Leocc::getReconfigurationState()
{
    return reconfigurationState;
}

void Leocc::setMinRtt(simtime_t minRtt)
{
    this->minRtt = minRtt;
}

simtime_t Leocc::getMinRtt()
{
    return minRtt;
}

void Leocc::setMinRttFluctation(simtime_t minRttFluct)
{
    minRttFluctuation = minRttFluct;
}

simtime_t Leocc::getMinRttFluctation()
{
    return minRttFluctuation;
}

}
}
