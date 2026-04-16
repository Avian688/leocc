//
// Linux-faithful LeoCC flavour for OMNeT++.
//

#include "LeoccFlavourFixed.h"

namespace inet {
namespace tcp {

Register_Class(LeoccFlavourFixed);

void LeoccFlavourFixed::handleProbeRTT()
{
    auto *leoccConn = check_and_cast<LeoccConnection *>(conn);
    auto *pacedConn = check_and_cast<TcpPacedConnection *>(conn);
    const uint32_t bytesInFlight = leoccConn->getBytesInFlight();
    const uint32_t appLimitedThreshold = state->m_delivered + bytesInFlight;

    // Linux LeoCC marks ProbeRTT samples app-limited at the TCP socket.
    pacedConn->setAppLimited(appLimitedThreshold != 0 ? appLimitedThreshold : 1);

    if (state->m_probeRttDoneStamp == 0) {
        if (bytesInFlight <= probeRttCwnd()) {
            state->m_probeRttDoneStamp = simTime() + state->m_probeRttDuration;
            state->m_probeRttRoundDone = false;
            state->m_nextRoundDelivered = state->m_delivered;
            conn->emit(nextRoundDeliveredSignal, state->m_nextRoundDelivered);
        }
        return;
    }

    if (state->m_roundStart)
        state->m_probeRttRoundDone = true;

    if (!state->m_probeRttRoundDone || simTime() <= state->m_probeRttDoneStamp)
        return;

    if (state->m_lastRtt > SIMTIME_ZERO)
        state->m_minRtt = state->m_lastRtt;
    state->m_minRttStamp = simTime();
    restoreCwnd();
    exitProbeRTT();

    if (state->local_reconfiguration_trigger) {
        // Mirror Linux's minmax_reset() on reconfiguration exit.
        m_maxBwFilter = MaxBandwidthFilter_t(state->m_bandwidthWindowLength, 0, state->m_roundCount);
        if (state->reconfiguration_max_bw > 0)
            m_maxBwFilter.Update(state->reconfiguration_max_bw, state->m_roundCount);
    }
}

} // namespace tcp
} // namespace inet
