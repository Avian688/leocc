//
// Copyright (C) 2001, 2003, 2004 Johnny Lai, Monash University, Melbourne, Australia
// Copyright (C) 2005 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include <algorithm> // std::sort
#include <cstddef>
#include <iostream>

#include <inet/applications/pingapp/PingApp_m.h>
#include <inet/common/ModuleAccess.h>
#include <inet/common/Protocol.h>
#include <inet/common/ProtocolGroup.h>
#include <inet/common/ProtocolTag_m.h>
#include <inet/common/lifecycle/ModuleOperations.h>
#include <inet/common/lifecycle/NodeStatus.h>
#include <inet/common/packet/chunk/ByteCountChunk.h>
#include <inet/networklayer/common/EchoPacket_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/IpProtocolId_m.h>
#include <inet/networklayer/common/L3AddressResolver.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/common/NetworkInterface.h>
#include <inet/networklayer/contract/IInterfaceTable.h>
#include <inet/networklayer/contract/IL3AddressType.h>
#include <inet/networklayer/contract/L3Socket.h>
#include <inet/networklayer/contract/ipv4/Ipv4Socket.h>
#include <inet/networklayer/contract/ipv6/Ipv6Socket.h>

#ifdef INET_WITH_IPv4
#include <inet/networklayer/ipv4/Icmp.h>
#include <inet/networklayer/ipv4/IcmpHeader.h>
#include <inet/networklayer/ipv4/Ipv4InterfaceData.h>
#endif // ifdef INET_WITH_IPv4

#ifdef INET_WITH_IPv6
#include <inet/networklayer/icmpv6/Icmpv6.h>
#include <inet/networklayer/icmpv6/Icmpv6Header_m.h>
#include <inet/networklayer/ipv6/Ipv6InterfaceData.h>
#endif // ifdef INET_WITH_IPv6

#include "LeoccPingApp.h"

namespace inet {

Define_Module(LeoccPingApp);


simsignal_t LeoccPingApp::responseIntervalSignal = registerSignal("responseInterval");

void LeoccPingApp::initialize(int stage)
{
    PingApp::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        reconfiguration_threshold = 0.045;
        last_time = SIMTIME_ZERO;

        global_reconfiguration_trigger_duration = SimTime(0.2);

        min_rtt_fluctuation_collection = false;
        rtt_sample_count = 0;

        reconfiguration_trigger_time_ms = SIMTIME_ZERO;
        reconfiguration_rtt_ms = SIMTIME_ZERO;

        local_rtt_sample_min = SIMTIME_MAX;
        local_rtt_sample_max = SIMTIME_ZERO;

        reconfiguration_min_rtt = SIMTIME_MAX;
        reconfiguration_max_rtt = SIMTIME_ZERO;

        cModule* parent = this->getParentModule();
        cModule* m = parent->getSubmodule("tcp");
        if (!m) {
            EV_WARN << "No TCP module found at LeoccPingApp!" << endl;
            return;
        }

        leoccMain = dynamic_cast<tcp::Leocc*>(m);
    }
}

void LeoccPingApp::processPingResponse(int originatorId, int seqNo, Packet *packet)
{
    const auto& pingPayload = packet->peekDataAt(B(0), packet->getDataLength());
    if (originatorId != pid) {
        EV_WARN << "Received response was not sent by this application, dropping packet\n";
        return;
    }

    // get src, hopCount etc from packet, and print them
    L3Address src = packet->getTag<L3AddressInd>()->getSrcAddress();
//    L3Address dest = msg->getTag<L3AddressInd>()->getDestination();
    auto& msgHopCountTag = packet->findTag<HopLimitInd>();
    int msgHopCount = msgHopCountTag ? msgHopCountTag->getHopLimit() : -1;

    // calculate the RTT time by looking up the the send time of the packet
    // if the send time is no longer available (i.e. the packet is very old and the
    // sendTime was overwritten in the circular buffer) then we just return a 0
    // to signal that this value should not be used during the RTT statistics)
    simtime_t rtt = SIMTIME_ZERO;
    bool isDup = false;

    if (sendSeqNo - seqNo < PING_HISTORY_SIZE) {
        int idx = seqNo % PING_HISTORY_SIZE;
        rtt = simTime() - sendTimeHistory[idx];

        //leoccMain->setMinRtt(rtt);

        isDup = pongReceived[idx];
        pongReceived[idx] = true;

        simtime_t cur_time_ms = simTime();
        bool global_reconfiguration_trigger = leoccMain->getReconfigurationState();
        if (global_reconfiguration_trigger && reconfiguration_trigger_time_ms > 0 && cur_time_ms >= reconfiguration_trigger_time_ms + global_reconfiguration_trigger_duration) {
            leoccMain->setReconfigurationState(false);
        }

        if (!min_rtt_fluctuation_collection && reconfiguration_trigger_time_ms > 0 && cur_time_ms >= reconfiguration_trigger_time_ms + reconfiguration_rtt_ms) {
            min_rtt_fluctuation_collection = true;
            rtt_sample_count = 0;
            reconfiguration_min_rtt = SIMTIME_MAX;
            reconfiguration_max_rtt = SIMTIME_ZERO;
            local_rtt_sample_min = SIMTIME_MAX;
            local_rtt_sample_max = SIMTIME_ZERO;
        }

        if (min_rtt_fluctuation_collection) {
            if (rtt_sample_count < RTT_SAMPLE_MAX) {
                rtt_samples[rtt_sample_count++] = rtt;
                if (rtt < local_rtt_sample_min)
                    local_rtt_sample_min = rtt;
                if (rtt > local_rtt_sample_max)
                    local_rtt_sample_max = rtt;
            } else {
                computePercentileRttRange(5, 95);
                reconfiguration_trigger_time_ms = 0;
            }
        }

        if(last_time > SIMTIME_ZERO) {
            if((simTime() - last_time) > reconfiguration_threshold) {
                leoccMain->setReconfigurationState(true);
                reconfiguration_trigger_time_ms = cur_time_ms;
                reconfiguration_rtt_ms = rtt;
            }
            emit(responseIntervalSignal, (simTime() - last_time));
        }
    last_time = simTime();
    }

    // update statistics
    countPingResponse(B(pingPayload->getChunkLength()).get(), seqNo, rtt, isDup);

}

void LeoccPingApp::computePercentileRttRange(uint32_t percentile_low, uint32_t percentile_high)
{
    min_rtt_fluctuation_collection = false;
    if (rtt_sample_count == 0) {
        return;
    }
    std::sort(rtt_samples, rtt_samples + rtt_sample_count);
    reconfiguration_min_rtt  = rtt_samples[rtt_sample_count * percentile_low / 100];
    reconfiguration_max_rtt = rtt_samples[rtt_sample_count * percentile_high / 100];
    simtime_t fluct = reconfiguration_max_rtt - reconfiguration_min_rtt;
    leoccMain->setMinRttFluctation(fluct);
}

} // namespace inet

