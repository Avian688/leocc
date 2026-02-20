//
// Copyright (C) 2001, 2003, 2004 Johnny Lai, Monash University, Melbourne, Australia
// Copyright (C) 2005 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#ifndef APPLICATIONS_PINGAPP_LEOCCPINGAPP_H_
#define APPLICATIONS_PINGAPP_LEOCCPINGAPP_H_

#include <inet/applications/pingapp/PingApp.h>

#include "../../transportlayer/leocc/Leocc.h"

#define RTT_SAMPLE_MAX 100

namespace inet {

/**
 * Generates LeoCC ping requests and calculates the packet loss and round trip
 * parameters of the replies.
 *
 * See NED file for detailed description of operation.
 */
class INET_API LeoccPingApp : public PingApp
{
  protected:
     tcp::Leocc* leoccMain;

     simtime_t last_time;
     simtime_t reconfiguration_threshold;

     simtime_t global_reconfiguration_trigger_duration;
     simtime_t rtt_samples[RTT_SAMPLE_MAX];
     bool min_rtt_fluctuation_collection;
     uint32_t rtt_sample_count;
     simtime_t reconfiguration_trigger_time_ms;
     simtime_t local_rtt_sample_min;
     simtime_t local_rtt_sample_max;
     simtime_t reconfiguration_rtt_ms;
     simtime_t reconfiguration_min_rtt;
     simtime_t reconfiguration_max_rtt;

     static simsignal_t responseIntervalSignal;
  protected:
     virtual void initialize(int stage) override;

     virtual void processPingResponse(int identifier, int seqNumber, Packet *packet) override;

     virtual void computePercentileRttRange(uint32_t percentile_low, uint32_t percentile_high);
};

} // namespace inet

#endif

