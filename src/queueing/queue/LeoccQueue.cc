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
#include <inet/transportlayer/tcp_common/TcpHeader_m.h>
#include <inet/common/PacketEventTag.h>
#include <inet/common/TimeTag.h>
#include <inet/networklayer/common/NetworkInterface.h>
#include "inet/common/ProtocolTag_m.h"
#include "LeoccQueue.h"

namespace inet {
namespace queueing {

Define_Module(LeoccQueue);

void LeoccQueue::initialize(int stage)
{
    PacketQueue::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        icmpQueue.setName("icmpStorage");
        if (packetComparatorFunction != nullptr)
            icmpQueue.setup(packetComparatorFunction);
    }
}

void LeoccQueue::pushPacket(Packet *packet, cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);

    bool isIcmp = false;
    cNamedObject packetPushStartedDetails("atomicOperationStarted");
    emit(packetPushStartedSignal, packet, &packetPushStartedDetails);
    EV_INFO << "Pushing packet" << EV_FIELD(packet) << EV_ENDL;

    auto ipv4Header = packet->removeAtFront<Ipv4Header>();
        if (ipv4Header->getTotalLengthField() < packet->getDataLength())
            packet->setBackOffset(B(ipv4Header->getTotalLengthField()) - ipv4Header->getChunkLength());

    if(ipv4Header->getProtocolId() == 1){ // 1 = ICMP data
        isIcmp = true;
        icmpQueue.insert(packet);
        if (packetDropperFunction != nullptr) {
            while (isIcmpOverloaded()) {
                auto packet = packetDropperFunction->selectPacket(this);
                EV_INFO << "Dropping packet" << EV_FIELD(packet) << EV_ENDL;
                icmpQueue.remove(packet);
                dropPacket(packet, QUEUE_OVERFLOW);
            }
        }
    }

    ipv4Header->setTotalLengthField(ipv4Header->getChunkLength() + packet->getDataLength());
    packet->insertAtFront(ipv4Header);

    if(!isIcmp){
        queue.insert(packet);
        if (buffer != nullptr)
            buffer->addPacket(packet);
        else if (packetDropperFunction != nullptr) {
            while (isOverloaded()) {
                auto packet = packetDropperFunction->selectPacket(this);
                EV_INFO << "Dropping packet" << EV_FIELD(packet) << EV_ENDL;
                queue.remove(packet);
                dropPacket(packet, QUEUE_OVERFLOW);
            }
        }
        ASSERT(!isOverloaded());
    }

    if (collector != nullptr && (getNumPackets() != 0 || icmpQueue.getLength() != 0))
        collector->handleCanPullPacketChanged(outputGate->getPathEndGate());

    cNamedObject packetPushEndedDetails("atomicOperationEnded");
    emit(packetPushEndedSignal, nullptr, &packetPushEndedDetails);
    updateDisplayString();
}

Packet *LeoccQueue::pullPacket(cGate *gate)
{
    Enter_Method("pullPacket");
    if(icmpQueue.getLength() > 0){
        auto packet = check_and_cast<Packet *>(icmpQueue.front());
        EV_INFO << "Pulling packet" << EV_FIELD(packet) << EV_ENDL;
        icmpQueue.pop();
        emit(packetPulledSignal, packet);
        animatePullPacket(packet, outputGate);
        updateDisplayString();
        return packet;
    }
    else{
        auto packet = check_and_cast<Packet *>(queue.front());
        EV_INFO << "Pulling packet" << EV_FIELD(packet) << EV_ENDL;
        queue.pop();

        auto queueingTime = simTime() - packet->getArrivalTime();
        auto packetEvent = new PacketQueuedEvent();
        packetEvent->setQueuePacketLength(getNumPackets());
        packetEvent->setQueueDataLength(getTotalLength());
        insertPacketEvent(this, packet, PEK_QUEUED, queueingTime, packetEvent);
        increaseTimeTag<QueueingTimeTag>(packet, queueingTime, queueingTime);
        emit(packetPulledSignal, packet);
        animatePullPacket(packet, outputGate);
        updateDisplayString();
        return packet;
    }
}

bool LeoccQueue::isIcmpOverloaded() const
{
    return (packetCapacity != -1 && icmpQueue.getLength() > packetCapacity) ||
           (dataCapacity != b(-1) && b(queue.getBitLength()) > dataCapacity);
}


} // namespace queueing
} // namespace inet
