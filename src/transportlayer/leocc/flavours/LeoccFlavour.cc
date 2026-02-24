//
// Copyright (C) 2020 Marcel Marek
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include <algorithm> // min,max

#include "LeoccFlavour.h"
#include "../Leocc.h"
#include "inet/transportlayer/tcp/flavours/TcpReno.h"

namespace inet {
namespace tcp {

#define MIN_REXMIT_TIMEOUT     0.2   // 1s
#define MAX_REXMIT_TIMEOUT     240   // 2 * MSL (RFC 1122)

double LeoccFlavour::PACING_GAIN_CYCLE[] = {5.0 / 4, 3.0 / 4, 1, 1, 1, 1, 1, 1};

Register_Class(LeoccFlavour);

simsignal_t LeoccFlavour::additiveIncreaseSignal = cComponent::registerSignal("additiveIncrease");
simsignal_t LeoccFlavour::minRttSignal = cComponent::registerSignal("minRtt");
simsignal_t LeoccFlavour::connMinRttSignal = cComponent::registerSignal("connMinRtt");
simsignal_t LeoccFlavour::maxBandwidthFilterSignal = cComponent::registerSignal("maxBandwidthFilter");
simsignal_t LeoccFlavour::stateSignal = cComponent::registerSignal("state");
simsignal_t LeoccFlavour::pacingGainSignal = cComponent::registerSignal("pacingGain");
simsignal_t LeoccFlavour::targetCwndSignal = cComponent::registerSignal("targetCwnd");
simsignal_t LeoccFlavour::priorCwndSignal = cComponent::registerSignal("priorCwnd");
simsignal_t LeoccFlavour::estimatedBdpSignal = cComponent::registerSignal("estimatedBdp");
simsignal_t LeoccFlavour::roundCountSignal = cComponent::registerSignal("roundCount");
simsignal_t LeoccFlavour::recoverSignal = cComponent::registerSignal("recover");
simsignal_t LeoccFlavour::lossRecoverySignal = cComponent::registerSignal("lossRecovery");
simsignal_t LeoccFlavour::highRxtSignal = cComponent::registerSignal("highRxt");
simsignal_t LeoccFlavour::recoveryPointSignal = cComponent::registerSignal("recoveryPoint");
simsignal_t LeoccFlavour::nextRoundDeliveredSignal = cComponent::registerSignal("nextRoundDelivered");
simsignal_t LeoccFlavour::restoreCwndSignal = cComponent::registerSignal("restoreCwnd");

LeoccFlavour::LeoccFlavour() : LeoccFamily(),
    state((LeoccStateVariables *&)TcpAlgorithm::state)
{
}

void LeoccFlavour::initialize()
{
    LeoccFamily::initialize();
}

void LeoccFlavour::established(bool active)
{
    if(!state->m_isInitialized){
        dynamic_cast<LeoccConnection*>(conn)->changeIntersendingTime(0.0000001); //do not pace intial packets as RTT is unknown

        // LeoCC specific variables.
        state->reconfiguration_max_bw = 0;
        state->use_max_filter = true;
        state->latest_bw = 0;
        state->kalman_gain_bw = 0;
        state->kalman_gain_rtt = 0;
        state->bw_hat_post = 0;
        state->rtt_hat_post = 0;
        state->p_post_bw = 25;
        state->p_post_rtt = 25;
        state->rtt_cnt_max_bw = 0;

        state->snd_cwnd = 4 * state->snd_mss; // RFC 2001
        state->m_minRtt = state->srtt != 0 ? state->srtt : SIMTIME_MAX;
        state->m_minRttStamp = simTime();
        state->m_initialCWnd = state->snd_cwnd;
        state->m_segmentSize = state->snd_mss;
        state->m_priorCwnd = state->snd_cwnd;
        recalculateSlowStartThreshold();
        state->m_targetCWnd = state->snd_cwnd;
        state->m_minPipeCwnd = 4 * state->m_segmentSize;
        state->m_sendQuantum = 1 * state->m_segmentSize;

        initRoundCounting();
        initFullPipe();
        enterStartup();
        initPacingRate();
        state->m_ackEpochTime = simTime();
        state->m_extraAckedWinRtt = 0;
        state->m_extraAckedIdx = 0;
        state->m_ackEpochAcked = 0;
        m_extraAcked[0] = 0;
        m_extraAcked[1] = 0;
        state->m_isInitialized = true;
    }
    //state->m_ackEpochTime = simTime();
    EV_DETAIL << "LEOCC initial CWND is set to " << state->snd_cwnd << "\n";
    if (active) {
        // finish connection setup with ACK (possibly piggybacked on data)
        EV_INFO << "Completing connection setup by sending ACK (possibly piggybacked on data)\n";
        sendData(false);
        conn->sendAck();
    }
}

void LeoccFlavour::recalculateSlowStartThreshold() {
    // RFC 2581, page 4:
    // "When a TCP sender detects segment loss using the retransmission
    // timer, the value of ssthresh MUST be set to no more than the value
    // given in equation 3:
    //
    //   ssthresh = max (FlightSize / 2, 2*SMSS)            (3)
    //
    // As discussed above, FlightSize is the amount of outstanding data in
    // the network."

    // set ssthresh to flight size / 2, but at least 2 SMSS
    // (the formula below practically amounts to ssthresh = cwnd / 2 most of the time)
//    uint32_t flight_size = state->snd_max - state->snd_una;
    //state->ssthresh = std::max(flight_size / 2, 2 * state->m_segmentSize);

    saveCwnd();
    conn->emit(ssthreshSignal, state->ssthresh);
}

void LeoccFlavour::processRexmitTimer(TcpEventCode &event) {
    TcpPacedFamily::processRexmitTimer(event);
    saveCwnd();
    state->m_roundStart = true;
    state->m_fullBandwidth = 0;
    state->snd_cwnd = state->snd_mss*4;
    conn->emit(cwndSignal, state->snd_cwnd);

    EV_INFO << " Rexmit Timeout! Recovery point: " << state->recoveryPoint << ", cwnd: "<< state->snd_cwnd << "\n";

    state->afterRto = true;
    tcp_state = CA_LOSS;
    dynamic_cast<TcpPacedConnection*>(conn)->cancelPaceTimer();
    sendData(false);
}

void LeoccFlavour::receivedDataAck(uint32_t firstSeqAcked)
{
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);
    EV_INFO << "receivedDataAck: firstSeqAcked" << firstSeqAcked << "\n";
    // Check if recovery phase has ended
    if (state->lossRecovery && state->sack_enabled) {
        if (seqGE(state->snd_una, state->recoveryPoint)) {

            EV_INFO   << " Loss Recovery terminated.\n";
            state->snd_cwnd = state->ssthresh;
            state->m_packetConservation = false;
            tcp_state = CA_OPEN;
            restoreCwnd();

            //state->snd_cwnd = state->ssthresh;
            state->lossRecovery = false;
            conn->emit(lossRecoverySignal, 0);
            EV_INFO << "lossRecovery = false, m_packetConservation = false, state->snd_cwnd = " << state->snd_cwnd << "\n";
        }
        else{
            dynamic_cast<TcpPacedConnection*>(conn)->doRetransmit();
            conn->emit(lossRecoverySignal, state->snd_cwnd);
        }
    }

    leoccMain();

    sendData(false);

    conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void LeoccFlavour::rttMeasurementComplete(simtime_t tSent, simtime_t tAcked)
{
    //
    // Jacobson's algorithm for estimating RTT and adaptively setting RTO.
    //
    // Note: this implementation calculates in doubles. An impl. which uses
    // 500ms ticks is available from old tcpmodule.cc:calcRetransTimer().
    //

    // update smoothed RTT estimate (srtt) and variance (rttvar)
    const double g = 0.125; // 1 / 8; (1 - alpha) where alpha == 7 / 8;
    simtime_t newRTT = tAcked - tSent;

    if(state->srtt == 0){
        state->srtt = newRTT;
    }

    simtime_t& srtt = state->srtt;
    simtime_t& rttvar = state->rttvar;

    simtime_t err = newRTT - srtt;

    srtt += g * err;
    rttvar += g * (fabs(err) - rttvar);

    // assign RTO (here: rexmit_timeout) a new value
    simtime_t rto = srtt + 4 * rttvar;

    if (rto > MAX_REXMIT_TIMEOUT)
        rto = MAX_REXMIT_TIMEOUT;
    else if (rto < MIN_REXMIT_TIMEOUT)
        rto = MIN_REXMIT_TIMEOUT;

    state->rexmit_timeout = rto;

    state->m_lastRtt = newRTT;
        dynamic_cast<TcpPacedConnection*>(conn)->setMinRtt(std::min(newRTT, dynamic_cast<TcpPacedConnection*>(conn)->getMinRtt()));

    // record statistics
    EV_DETAIL << "Measured RTT=" << (newRTT * 1000) << "ms, updated SRTT=" << (srtt * 1000)
              << "ms, new RTO=" << (rto * 1000) << "ms\n";

    conn->emit(rttSignal, newRTT);
    conn->emit(srttSignal, srtt);
    conn->emit(rttvarSignal, rttvar);
    conn->emit(rtoSignal, rto);
    conn->emit(connMinRttSignal, dynamic_cast<LeoccConnection*>(conn)->getMinRtt());
}

void LeoccFlavour::updateModelAndState()
{
    updateBottleneckBandwidth();
    updateAckAggregation();
    checkCyclePhase();
    checkFullPipe();
    checkDrain();
    updateRTprop();
    checkProbeRTT();
}

void LeoccFlavour::updateControlParameters()
{
    setPacingRate(state->m_pacingGain);
    setSendQuantum();
    setCwnd();
}

void LeoccFlavour::updateBottleneckBandwidth()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    if(rs.m_delivered < 0 || rs.m_interval == 0) {
        return;
    }

    updateRound();

    if (rs.m_deliveryRate > state->rtt_cnt_max_bw)
        state->rtt_cnt_max_bw = rs.m_deliveryRate;

    if (m_state == LeoccMode_t::LEOCC_PROBE_RTT && state->m_lastRtt > 0 && state->rtt_hat_post > state->m_lastRtt + delta_thresh) {
        state->reconfiguration_max_bw = state->latest_bw;
    }

    if (rs.m_deliveryRate >= m_maxBwFilter.GetBest() || !rs.m_isAppLimited)
    {
        m_maxBwFilter.Update(rs.m_deliveryRate, state->m_roundCount);
    }
    state->latest_bw = rs.m_deliveryRate;
}

void LeoccFlavour::updateAckAggregation()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    uint32_t expectedAcked;
    uint32_t extraAck;
    uint32_t epochProp;
    if (!state->m_extraAckedGain || rs.m_ackedSacked <= 0 || rs.m_delivered < 0)
    {
        return;
    }

    if (state->m_roundStart)
    {
        state->m_extraAckedWinRtt = std::min<uint32_t>(31, state->m_extraAckedWinRtt + 1);
        if (state->m_extraAckedWinRtt >= state->m_extraAckedWinRttLength)
        {
            state->m_extraAckedWinRtt = 0;
            state->m_extraAckedIdx = state->m_extraAckedIdx ? 0 : 1;
            m_extraAcked[state->m_extraAckedIdx] = 0;
        }
    }

    epochProp = simTime().dbl() - state->m_ackEpochTime.dbl();
    expectedAcked = m_maxBwFilter.GetBest() * epochProp;

    if (state->m_ackEpochAcked <= expectedAcked ||
        (state->m_ackEpochAcked + rs.m_ackedSacked >= state->m_ackEpochAckedResetThresh))
    {
        state->m_ackEpochAcked = 0;
        state->m_ackEpochTime = simTime();
        expectedAcked = 0;
    }

    state->m_ackEpochAcked = state->m_ackEpochAcked + rs.m_ackedSacked;
    extraAck = state->m_ackEpochAcked - expectedAcked;
    extraAck = std::min(extraAck, state->snd_cwnd);

    if (extraAck > m_extraAcked[state->m_extraAckedIdx])
    {
        m_extraAcked[state->m_extraAckedIdx] = extraAck;
    }
}

void LeoccFlavour::checkCyclePhase()
{
    if(m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE && isNextCyclePhase())
    {
        advanceCyclePhase();
    }
}

void LeoccFlavour::checkFullPipe()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    if (state->m_isPipeFilled || !state->m_roundStart || rs.m_isAppLimited)
    {
        return;
    }

    /* Check if Bottleneck bandwidth is still growing*/
    if (m_maxBwFilter.GetBest() >= ((uint32_t)(state->m_fullBandwidth * 1.25)))
    {
        state->m_fullBandwidth = m_maxBwFilter.GetBest();
        state->m_fullBandwidthCount = 0;
        return;
    }
    state->m_fullBandwidthCount++;
    if (state->m_fullBandwidthCount >= 3)
    {
        state->m_isPipeFilled = true;
        EV_INFO   << " Pipe is filled. state->m_isPipeFilled = true m_fullBandwidth" << state->m_fullBandwidth << "\n";
    }
}

void LeoccFlavour::checkDrain()
{
    if (m_state == LeoccMode_t::LEOCC_STARTUP && state->m_isPipeFilled)
    {
        state->reconfiguration_max_bw = 0;

        state->local_reconfiguration_trigger = false;

        enterDrain();
        state->ssthresh = inFlight(1);
        conn->emit(ssthreshSignal, state->ssthresh);
    }

    //Bytes in flight is per rtt
    if (m_state == LeoccMode_t::LEOCC_DRAIN && dynamic_cast<LeoccConnection*>(conn)->getBytesInFlight() <= inFlight(1))
    {
        enterProbeBW();
    }
}

void LeoccFlavour::updateRTprop()
{
    state->m_minRttExpired = simTime() > (state->m_minRttStamp + state->m_minRttFilterLen);
    if (state->m_lastRtt >= 0 && (state->m_lastRtt <= state->m_minRtt || state->m_minRttExpired))
    {
        state->m_minRtt = state->m_lastRtt;
        state->m_minRttStamp = simTime();

        conn->emit(minRttSignal, state->m_minRtt);
    }
}

void LeoccFlavour::checkProbeRTT()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    if (m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE && (state->m_minRttExpired || state->local_reconfiguration_trigger) && !state->m_idleRestart)
    {
        enterProbeRTT();
        state->m_probeRttDoneStamp = 0;
        saveCwnd();
    }

    if (m_state == LeoccMode_t::LEOCC_PROBE_RTT)
    {
        handleProbeRTT();
    }

    if (rs.m_delivered)
    {
        state->m_idleRestart = false;
    }
}

void LeoccFlavour::updateRound()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();

    if (rs.m_priorDelivered >= state->m_nextRoundDelivered)
    {
        state->m_nextRoundDelivered = state->m_delivered;
        state->m_roundCount++;
        state->rtt_cnt_max_bw = 0;
        state->m_roundStart = true;
        state->m_packetConservation = false;

        conn->emit(roundCountSignal, state->m_roundCount);
        conn->emit(nextRoundDeliveredSignal, state->m_nextRoundDelivered);
    }
    else
    {
        state->m_roundStart = false;
    }

}

bool LeoccFlavour::isNextCyclePhase()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    bool isFullLength = (simTime() - state->m_cycleStamp) > state->m_minRtt;
    if (state->m_pacingGain == 1)
    {
        return isFullLength;
    }
    else if (state->m_pacingGain > 1)
    {
        return isFullLength &&
               (rs.m_bytesLoss > 0 || rs.m_priorInFlight >= inFlight(state->m_pacingGain));
    }
    else
    {
        return isFullLength || rs.m_priorInFlight <= inFlight(1);
    }
}

void LeoccFlavour::advanceCyclePhase()
{
    state->m_cycleStamp = simTime();
    state->m_cycleIndex = (state->m_cycleIndex + 1) % GAIN_CYCLE_LENGTH;
    state->m_pacingGain = PACING_GAIN_CYCLE[state->m_cycleIndex];
    conn->emit(pacingGainSignal, state->m_pacingGain);
}

uint32_t LeoccFlavour::inFlight(double gain)
{
    uint32_t bw = m_maxBwFilter.GetBest();
    if(state->useBwHatPost){
        bw = state->bw_hat_post;
    }
    if (state->m_minRtt == SIMTIME_MAX)
    {
        return state->m_initialCWnd;
    }
    double quanta = 3 * state->m_sendQuantum;
    double estimatedBdp = ((double)bw) * state->m_minRtt.dbl();
    conn->emit(estimatedBdpSignal, estimatedBdp);

    if (m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE && state->m_cycleIndex == 0)
    {
        return (gain * estimatedBdp) + quanta + (2 * state->m_segmentSize);
    }
    return (gain * estimatedBdp) + quanta;
}

void LeoccFlavour::enterDrain()
{
    setLeoccState(LeoccMode_t::LEOCC_DRAIN);
    state->m_pacingGain = (double) 1.0 / state->m_highGain;
    state->m_cWndGain = state->m_highGain;

    EV_INFO   << " Entering Drain.  m_pacingGain = " << state->m_pacingGain << "m_cWndGain = " << state->m_highGain << "\n";
}

void LeoccFlavour::enterProbeBW()
{
    setLeoccState(LeoccMode_t::LEOCC_DYNAMIC_CRUISE);
    state->m_pacingGain = 1;
    state->m_cWndGain = 2;
    boost::random::uniform_int_distribution<> dist(0, 6);
    state->m_cycleIndex = GAIN_CYCLE_LENGTH - 1 - (int)dist(gen);

    EV_INFO   << " Entering ProbeBW.  m_pacingGain = " << state->m_pacingGain << "m_cWndGain = " << state->m_highGain << "\n";

    advanceCyclePhase();

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void LeoccFlavour::setLeoccState(LeoccMode_t mode)
{
    m_state = mode;
    EV_INFO   << " Setting LEOCC State: " << m_state << "\n";
    conn->emit(stateSignal, m_state);
}

void LeoccFlavour::enterProbeRTT()
{
    setLeoccState(LeoccMode_t::LEOCC_PROBE_RTT);
    state->m_pacingGain = 1;
    state->m_cWndGain = 1;

    EV_INFO   << " Entering ProbeRTT.  m_pacingGain = " << state->m_pacingGain << "m_cWndGain = " << state->m_highGain << "\n";

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void LeoccFlavour::handleProbeRTT()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    uint32_t totalBytes = state->m_delivered + dynamic_cast<LeoccConnection*>(conn)->getBytesInFlight();
    state->m_appLimited = false;

    if (state->m_probeRttDoneStamp == 0 && dynamic_cast<LeoccConnection*>(conn)->getBytesInFlight() <= state->m_minPipeCwnd)
    {
        state->m_probeRttDoneStamp = simTime() + state->m_probeRttDuration;
        state->m_probeRttRoundDone = false;
        state->m_nextRoundDelivered = state->m_delivered;

        conn->emit(nextRoundDeliveredSignal, state->m_nextRoundDelivered);
    }
    else if (state->m_probeRttDoneStamp != 0)
    {
        if (state->m_roundStart)
        {
            state->m_probeRttRoundDone = true;
           //TODO may need fixing!
            state->m_minRtt = state->m_lastRtt;
            state->m_minRttStamp = simTime();

        }
        if (state->m_probeRttRoundDone && simTime() > state->m_probeRttDoneStamp)
        {
            state->m_minRttStamp = simTime();
            restoreCwnd();
            exitProbeRTT();

            if (state->local_reconfiguration_trigger) {
                //minmax_reset for Leocc. Resets filter after local_reconfiguration
                m_maxBwFilter = MaxBandwidthFilter_t(state->m_bandwidthWindowLength, state->snd_cwnd / rtt.dbl(), state->reconfiguration_max_bw);
            }
        }
    }
}

void LeoccFlavour::saveCwnd()
{
    if ((!state->lossRecovery) && m_state != LeoccMode_t::LEOCC_PROBE_RTT)
    {
        state->m_priorCwnd = state->snd_cwnd;
    }
    else
    {
        state->m_priorCwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    }

    EV_INFO << " SaveCwnd.  snd_cwnd = " << state->snd_cwnd << "m_priorCwnd = " << state->m_priorCwnd << "\n";
    conn->emit(priorCwndSignal, state->m_priorCwnd);
}

void LeoccFlavour::restoreCwnd()
{
    state->snd_cwnd = std::max(state->m_priorCwnd, state->snd_cwnd);
    EV_INFO << " RestoreCwnd.  snd_cwnd = " << state->snd_cwnd << "\n";
    conn->emit(restoreCwndSignal, state->snd_cwnd);
}

void LeoccFlavour::exitProbeRTT()
{
    if(!state->m_isPipeFilled || state->local_reconfiguration_trigger)
    {
        EV_INFO << " Exiting ProbeRTT. m_isPipeFilled = false. Entering Startup.\n";
        enterStartup();
    }
    else
    {
        EV_INFO << " Exiting ProbeRTT. m_isPipeFilled = true\n";
        enterProbeBW();
    }
}

void LeoccFlavour::enterStartup()
{
    setLeoccState(LeoccMode_t::LEOCC_STARTUP);

    //LeoCC specific setting
    state->m_isPipeFilled = false;
    state->m_fullBandwidth = 0;
    state->m_fullBandwidthCount = 0;
    //

    state->m_pacingGain = state->m_highGain;
    state->m_cWndGain = state->m_highGain;

    EV_INFO << " Entering Startup.  m_pacingGain = " << state->m_pacingGain << "m_cWndGain = " << state->m_highGain << "\n";

    conn->emit(pacingGainSignal, state->m_pacingGain);
}

void LeoccFlavour::setPacingRate(double gain)
{
    uint32_t bw = m_maxBwFilter.GetBest();
    if(state->useBwHatPost){
        bw = state->bw_hat_post;
    }
    uint32_t rate = (double) gain * (double) bw;
    rate *= (1.f - state->m_pacingMargin);
    uint32_t maxRate = 500000000; // 4Gbps
    rate = std::min(rate, maxRate);
    if (!state->m_hasSeenRtt && dynamic_cast<LeoccConnection*>(conn)->getMinRtt() != SIMTIME_MAX)
    {
        initPacingRate();
    }

    //double pace = state->m_minRtt.dbl()/(((double)rate*state->m_lastRtt.dbl())/(double)state->m_segmentSize);
    double pace = (double)1/(((double)rate)/(double)state->m_segmentSize+59);
    if ((state->m_isPipeFilled || pace < dynamic_cast<LeoccConnection*>(conn)->getPacingRate().dbl()) && rate > 0)
    {
        dynamic_cast<LeoccConnection*>(conn)->changeIntersendingTime(pace);
        EV_INFO << " Setting pacing rate = " << pace << "\n";
    }
}

void LeoccFlavour::setSendQuantum()
{
    state->m_sendQuantum = 1 * state->m_segmentSize;
}

void LeoccFlavour::setCwnd()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    if (!rs.m_ackedSacked)
    {
        goto done;
    }
    if (state->lossRecovery)
    {
        if (modulateCwndForRecovery())
        {
            goto done;
        }
    }

    updateTargetCwnd();

    if (state->m_isPipeFilled)
    {
        state->snd_cwnd = std::min(state->snd_cwnd + (uint32_t)rs.m_ackedSacked, state->m_targetCWnd);
    }
    else if (state->snd_cwnd  < state->m_targetCWnd || state->m_delivered < state->m_initialCWnd) //* snd_mss
    {
        state->snd_cwnd  = state->snd_cwnd  + rs.m_ackedSacked;
    }
    state->snd_cwnd  = std::max(state->snd_cwnd , state->m_minPipeCwnd);
    EV_INFO << " Setting CWND to = " << state->snd_cwnd << "\n";
done:
    modulateCwndForProbeRTT();
}

bool LeoccFlavour::modulateCwndForRecovery()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection*>(conn)->getRateSample();
    if (rs.m_bytesLoss > 0)
    {
       state->snd_cwnd = std::max((int)state->snd_cwnd  - (int)rs.m_bytesLoss, (int)state->m_segmentSize);
       EV_INFO << "modulateCwndForRecovery.  rs.m_bytesLoss > 0 Setting cwnd to: " <<  state->snd_cwnd << "\n";
    }

    if (state->m_packetConservation)
    {
       state->snd_cwnd = std::max(state->snd_cwnd , dynamic_cast<LeoccConnection*>(conn)->getBytesInFlight() + rs.m_ackedSacked);
       EV_INFO << "modulateCwndForRecovery.  state->m_packetConservation = true. Setting cwnd to: " <<  state->snd_cwnd << "\n";
       //think its here
       return true;
    }
    return false;
}

uint32_t LeoccFlavour::probeRttCwnd()
{
    return std::max(state->m_minPipeCwnd, inFlight(leocc_probe_rtt_cwnd_gain));
}

void LeoccFlavour::modulateCwndForProbeRTT()
{
    if (m_state == LeoccMode_t::LEOCC_PROBE_RTT)
    {
        state->snd_cwnd = std::min(state->snd_cwnd, probeRttCwnd());
        EV_INFO << "modulateCwndForProbeRTT. Setting cwnd to: " <<  state->snd_cwnd << "\n";
    }
}

void LeoccFlavour::initPacingRate()
{
    //if (!tcb->m_pacing)
    //{
    //    NS_LOG_WARN("LEOCC must use pacing");
    //    tcb->m_pacing = true;
    //}

    simtime_t rtt;
    simtime_t connMinRtt = dynamic_cast<LeoccConnection*>(conn)->getMinRtt();
    if (connMinRtt != SIMTIME_MAX)
    {
        if (connMinRtt < 0.001){
            rtt = 0.001;
        }
        else{
            rtt = connMinRtt;
        }
        state->m_hasSeenRtt = true;
    }
    else
    {
        rtt = SimTime(0.001);
    }

    uint32_t nominalBandwidth = (state->snd_cwnd / rtt.dbl()); //* 8 / rtt.dbl());
    if((state->m_pacingGain * (double) nominalBandwidth) > 0){
        double pace = 1/((state->m_pacingGain *(double)nominalBandwidth)/(double)state->m_segmentSize);
        dynamic_cast<LeoccConnection*>(conn)->changeIntersendingTime(pace);
    }
    m_maxBwFilter = MaxBandwidthFilter_t(state->m_bandwidthWindowLength, state->snd_cwnd / rtt.dbl(), 0);// * 8 / rtt.dbl(), 0);
}

void LeoccFlavour::updateTargetCwnd()
{
    state->m_targetCWnd = inFlight(state->m_cWndGain);// + ackAggregationCwnd();

    EV_INFO << "updateTargetCwnd to " << state->m_targetCWnd << "\n";
    conn->emit(targetCwndSignal, state->m_targetCWnd);
}

uint32_t LeoccFlavour::ackAggregationCwnd()
{
    uint32_t maxAggrBytes; // MaxBW * 0.1 secs
    uint32_t aggrCwndBytes = 0;

    if (state->m_extraAckedGain && state->m_isPipeFilled)
    {
        maxAggrBytes = m_maxBwFilter.GetBest() * 0.1;
        aggrCwndBytes = state->m_extraAckedGain * std::max(m_extraAcked[0], m_extraAcked[1]);
        aggrCwndBytes = std::min(aggrCwndBytes, maxAggrBytes);
    }
    return aggrCwndBytes;
}

void LeoccFlavour::initRoundCounting()
{
    state->m_nextRoundDelivered = 0;
    state->m_roundStart = false;
    state->m_roundCount = 0;
}

void LeoccFlavour::initFullPipe()
{
    state->m_isPipeFilled = false;
    state->m_fullBandwidth = 0;
    state->m_fullBandwidthCount = 0;
}

void LeoccFlavour::receivedDuplicateAck()
{
    bool isHighRxtLost = dynamic_cast<TcpPacedConnection*>(conn)->checkIsLost(state->snd_una+state->snd_mss);
    EV_INFO << "dupAck received. Total DupAcks: " << state->dupacks << "\n";
    //bool isHighRxtLost = false;
    bool rackLoss = dynamic_cast<TcpPacedConnection*>(conn)->checkRackLoss();
    if ((rackLoss && !state->lossRecovery) || state->dupacks == state->dupthresh || (isHighRxtLost && !state->lossRecovery)) {
            EV_INFO << "dupAcks == DUPTHRESH(=" << state->dupthresh << ": perform Fast Retransmit, and enter Fast Recovery:";

            if (state->sack_enabled) {
                if (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) { // HighACK = snd_una
                    //mark head as lost
                    state->recoveryPoint = state->snd_max; // HighData = snd_max
                    saveCwnd();
                    state->lossRecovery = true;
                    conn->emit(recoveryPointSignal, state->recoveryPoint);

                    dynamic_cast<TcpPacedConnection*>(conn)->setSackedHeadLost();
                    dynamic_cast<TcpPacedConnection*>(conn)->updateInFlight();
                    tcp_state = CA_RECOVERY;
                    EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
                    //state->snd_cwnd = state->ssthresh;
                    state->snd_cwnd = dynamic_cast<LeoccConnection*>(conn)->getBytesInFlight() + std::max(dynamic_cast<TcpPacedConnection*>(conn)->getLastAckedSackedBytes(), state->m_segmentSize);
                    state->m_packetConservation = true;
                    dynamic_cast<TcpPacedConnection*>(conn)->doRetransmit();
                    conn->emit(recoveryPointSignal, state->recoveryPoint);
                }
            }

            if (state->sack_enabled) {
                if (state->lossRecovery) {
                    EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();
                }
            }
            EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
            conn->emit(highRxtSignal, state->highRxt);
    }
    else if (state->dupacks > state->dupthresh) {

        EV_INFO << "dupAcks > DUPTHRESH(=" << state->dupthresh << ": Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

    }

    leoccMain();

    sendData(false);

    conn->emit(maxBandwidthFilterSignal, m_maxBwFilter.GetBest());
    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(pacingGainSignal, state->m_pacingGain);

    if(state->lossRecovery){
        conn->emit(lossRecoverySignal, state->snd_cwnd);
    }

}

void LeoccFlavour::leoccMain()
{
    //simtime_t min_rtt_us =  dynamic_cast<tcp::Leocc*>(conn->getTcpMain())->getMinRtt();
    global_reconfiguration_trigger = dynamic_cast<tcp::Leocc*>(conn->getTcpMain())->getReconfigurationState();

    state->m_delivered = dynamic_cast<TcpPacedConnection*>(conn)->getDelivered();
    if (global_reconfiguration_trigger && !state->local_reconfiguration_trigger) {
        state->local_reconfiguration_trigger = true;
    }

    if (m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE && !(state->m_delivered < state->m_nextRoundDelivered)) {
        state->p_post_bw = state->p_post_bw + var_Q;
        state->kalman_gain_bw = state->p_post_bw / (state->p_post_bw + var_R);
        state->bw_hat_post = ((state->kalman_gain_bw) * state->bw_hat_post + state->kalman_gain_bw * state->rtt_cnt_max_bw);
        state->p_post_bw = (state->kalman_gain_bw) * state->p_post_bw;
    }

    updateModelAndState();

    //TODO Verify that state->m_lastRtt = rs->rtt_us
    if (state->m_lastRtt > 0) {
        state->p_post_rtt = state->p_post_rtt + var_Q_rtt;
        state->kalman_gain_rtt = state->p_post_rtt / (state->p_post_rtt + var_R_rtt);
        state->rtt_hat_post = ((state->kalman_gain_rtt) * state->rtt_hat_post + state->kalman_gain_rtt * state->m_lastRtt);
        state->p_post_rtt = (state->kalman_gain_rtt) * state->p_post_rtt;
    }

    state->use_max_filter = true;

    if (min_rtt_fluctuation > 0 && state->rtt_hat_post >= delta_rtt + state->m_minRtt + min_rtt_fluctuation && !state->local_reconfiguration_trigger && m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE)
    {
        state->use_max_filter = false;
        state->useBwHatPost = true;
        PACING_GAIN_CYCLE[0] = 21 / 20;
    } else {
        PACING_GAIN_CYCLE[0] = 5 / 4;
    }

    updateControlParameters();
    state->useBwHatPost = false;
}

} // namespace tcp
} // namespace inet
