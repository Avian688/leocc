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

#ifndef QUEUEING_QUEUE_LEOCCQUEUE_H_
#define QUEUEING_QUEUE_LEOCCQUEUE_H_

#include <map>
#include "inet/queueing/queue/PacketQueue.h"

namespace inet {
namespace queueing {

class LeoccQueue : public PacketQueue {
protected:
    cPacketQueue icmpQueue;

protected:
    virtual void initialize(int stage) override;
    virtual bool isIcmpOverloaded() const;
    virtual Packet *getIcmpPacket(int index) const;

    bool bothQueuesEmpty() const;
    Packet *peekPreferredPacket() const;  // icmpQueue first, then queue

public:
    virtual void pushPacket(Packet *packet, cGate *gate) override;
    virtual Packet *pullPacket(cGate *gate) override;

    virtual bool canPullSomePacket(cGate *gate) const override;
    virtual Packet *canPullPacket(cGate *gate) const override;

};

} // namespace queueing
}// namespace inet

#endif /* QUEUEING_QUEUE_LEOCCQUEUE_H_ */
