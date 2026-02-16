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

#ifndef TRANSPORTLAYER_LEOCC_LEOCC_H_
#define TRANSPORTLAYER_LEOCC_LEOCC_H_

#include <inet/transportlayer/tcp/TcpConnection.h>
#include "../../../../tcpPaced/src/transportlayer/tcp/TcpPaced.h"
#include "LeoccConnection.h"

namespace inet {
namespace tcp {

class Leocc : public TcpPaced {
public:
    Leocc();
    virtual ~Leocc();
protected:
    bool reconfigurationState;
    simtime_t minRtt;
    simtime_t minRttFluctuation;
protected:
    virtual void initialize(int stage) override;
    /** Factory method; may be overriden for customizing Tcp */
    virtual TcpConnection* createConnection(int socketId) override;
public:
    virtual void setReconfigurationState(bool reconfiguration);
    virtual bool getReconfigurationState();

    virtual void setMinRtt(simtime_t minRtt);
    virtual simtime_t getMinRtt();

    virtual void setMinRttFluctation(simtime_t minRttFluct);
    virtual simtime_t getMinRttFluctation();
};

} // namespace tcp
} // namespace inet

#endif /* TRANSPORTLAYER_BBR_BBR_H_ */
