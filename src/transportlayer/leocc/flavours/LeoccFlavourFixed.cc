//
// Comparison-only LeoCC flavour with proposed fixes.
// This file is intentionally not referenced by the build or NED files.
//

#include "LeoccFlavourFixed.h"
#include "../Leocc.h"

namespace inet {
namespace tcp {

void LeoccFlavourFixed::updateBottleneckBandwidth()
{
    LeoccConnection::RateSample rs = dynamic_cast<LeoccConnection *>(conn)->getRateSample();
    if (rs.m_delivered < 0 || rs.m_interval == 0)
        return;

    updateRound();

    if (rs.m_deliveryRate > state->rtt_cnt_max_bw)
        state->rtt_cnt_max_bw = rs.m_deliveryRate;

    if (m_state == LeoccMode_t::LEOCC_PROBE_RTT && state->m_lastRtt > 0 &&
        state->rtt_hat_post > state->m_lastRtt + delta_thresh)
        state->reconfiguration_max_bw = state->latest_bw;

    if (rs.m_deliveryRate >= m_maxBwFilter.GetBest() || !rs.m_isAppLimited)
        m_maxBwFilter.Update(rs.m_deliveryRate, state->m_roundCount);

    state->latest_bw = rs.m_deliveryRate;
}

void LeoccFlavourFixed::handleProbeRTT()
{
    auto *leoccConn = dynamic_cast<LeoccConnection *>(conn);
    const uint32_t bytesInFlight = leoccConn->getBytesInFlight();

    // Keep ProbeRTT app-limited while draining inflight, matching the Linux intent.
    state->m_appLimited = (state->m_delivered + bytesInFlight) == 0 ? 1 : state->m_appLimited;

    if (state->m_probeRttDoneStamp == 0 && bytesInFlight <= probeRttCwnd()) {
        state->m_probeRttDoneStamp = simTime() + state->m_probeRttDuration;
        state->m_probeRttRoundDone = false;
        state->m_nextRoundDelivered = state->m_delivered;
        conn->emit(nextRoundDeliveredSignal, state->m_nextRoundDelivered);
        return;
    }

    if (state->m_probeRttDoneStamp == 0)
        return;

    if (state->m_roundStart)
        state->m_probeRttRoundDone = true;

    if (!state->m_probeRttRoundDone || simTime() <= state->m_probeRttDoneStamp)
        return;

    if (state->m_lastRtt > 0)
        state->m_minRtt = state->m_lastRtt;
    state->m_minRttStamp = simTime();
    restoreCwnd();
    exitProbeRTT();

    if (state->local_reconfiguration_trigger) {
        // Match Linux's minmax_reset() semantics more closely by resetting the
        // filter at the current round and then seeding it with the saved bw.
        m_maxBwFilter = MaxBandwidthFilter_t(state->m_bandwidthWindowLength, 0, state->m_roundCount);
        if (state->reconfiguration_max_bw > 0)
            m_maxBwFilter.Update(state->reconfiguration_max_bw, state->m_roundCount);
    }
}

void LeoccFlavourFixed::leoccMain()
{
    auto *leoccMain = dynamic_cast<tcp::Leocc *>(conn->getTcpMain());
    global_reconfiguration_trigger = leoccMain->getReconfigurationState();
    min_rtt_fluctuation = leoccMain->getMinRttFluctation();

    state->m_delivered = dynamic_cast<TcpPacedConnection *>(conn)->getDelivered();

    // Latch the trigger on the rising edge so a sticky global trigger does not
    // keep re-entering the reconfiguration path after each recovery.
    if (global_reconfiguration_trigger && !previousGlobalReconfigurationTrigger &&
        !state->local_reconfiguration_trigger)
        state->local_reconfiguration_trigger = true;
    previousGlobalReconfigurationTrigger = global_reconfiguration_trigger;

    if (m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE &&
        !(state->m_delivered < state->m_nextRoundDelivered)) {
        state->p_post_bw = state->p_post_bw + var_Q;
        state->kalman_gain_bw = static_cast<double>(state->p_post_bw) / (state->p_post_bw + var_R);
        state->bw_hat_post = static_cast<uint32_t>(
            ((1.0 - state->kalman_gain_bw) * state->bw_hat_post) +
            (state->kalman_gain_bw * state->rtt_cnt_max_bw));
        state->p_post_bw = static_cast<uint32_t>((1.0 - state->kalman_gain_bw) * state->p_post_bw);
    }

    updateModelAndState();

    if (state->m_lastRtt > 0) {
        state->p_post_rtt = state->p_post_rtt + var_Q_rtt;
        state->kalman_gain_rtt = static_cast<double>(state->p_post_rtt) / (state->p_post_rtt + var_R_rtt);
        state->rtt_hat_post =
            ((1.0 - state->kalman_gain_rtt) * state->rtt_hat_post) +
            (state->kalman_gain_rtt * state->m_lastRtt);
        state->p_post_rtt = static_cast<uint32_t>((1.0 - state->kalman_gain_rtt) * state->p_post_rtt);
    }

    state->use_max_filter = true;
    if (min_rtt_fluctuation > 0 &&
        state->rtt_hat_post >= delta_rtt + state->m_minRtt + min_rtt_fluctuation &&
        !state->local_reconfiguration_trigger &&
        m_state == LeoccMode_t::LEOCC_DYNAMIC_CRUISE) {
        state->use_max_filter = false;
        state->useBwHatPost = true;
        PACING_GAIN_CYCLE[0] = 1.05;
    }
    else {
        PACING_GAIN_CYCLE[0] = 1.25;
    }

    updateControlParameters();
    state->useBwHatPost = false;
}

} // namespace tcp
} // namespace inet
