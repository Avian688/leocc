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

#ifndef TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOUR_H_
#define TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOUR_H_

#include <random>
#include "../LeoccConnection.h"
#include "LeoccFamily.h"
#include "windowedfilter.h"
#include "LeoccFamilyState_m.h"
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random.hpp>
namespace inet {
namespace tcp {

/**
 * State variables for Leocc.
 */
typedef LeoccFamilyStateVariables LeoccStateVariables;

/**
 * Implements Leocc.
 */
class LeoccFlavour : public LeoccFamily
{
  public:

    static const uint8_t GAIN_CYCLE_LENGTH = 8;

    static double PACING_GAIN_CYCLE[];

    enum LeoccMode_t
    {
        LEOCC_STARTUP,   /**< Ramp up sending rate rapidly to fill pipe */
        LEOCC_DRAIN,     /**< Drain any queue created during startup */
        LEOCC_DYNAMIC_CRUISE,  /**< Discover, share bw: pace around estimated bw */
        LEOCC_PROBE_RTT, /**< Cut inflight to min to probe min_rtt */
    };

    enum LeoccState
       {
           CA_OPEN,
           CA_LOSS,
           CA_RECOVERY,
       };

    typedef WindowedFilter<uint32_t,
                               MaxFilter<uint32_t>,
                               uint32_t,
                               uint32_t>
            MaxBandwidthFilter_t;

  protected:
    LeoccStateVariables *& state;
    static simsignal_t additiveIncreaseSignal;
    static simsignal_t minRttSignal;
    static simsignal_t maxBandwidthFilterSignal;
    static simsignal_t stateSignal;
    static simsignal_t pacingGainSignal;
    static simsignal_t targetCwndSignal;
    static simsignal_t estimatedBdpSignal;
    static simsignal_t priorCwndSignal;
    static simsignal_t roundCountSignal;

    static simsignal_t recoverSignal;
    static simsignal_t lossRecoverySignal;
    static simsignal_t highRxtSignal;
    static simsignal_t recoveryPointSignal;
    static simsignal_t connMinRttSignal;
    static simsignal_t nextRoundDeliveredSignal;
    static simsignal_t restoreCwndSignal;

    simtime_t rtt;
    boost::random::mt19937 gen{6};
    uint32_t m_extraAcked[2] = {0, 0};

    LeoccMode_t m_state{LeoccMode_t::LEOCC_STARTUP};
    LeoccState tcp_state = LeoccState::CA_OPEN;
    MaxBandwidthFilter_t m_maxBwFilter;

    double leocc_probe_rtt_cwnd_gain = 1/2;
    simtime_t delta_thresh = 0.045; //values
    simtime_t delta_rtt = 0;
    bool global_reconfiguration_trigger = false;
    simtime_t min_rtt_fluctuation = 0;

    const uint32_t var_R = 4; //TODO CHECK THESE VALUES
    const uint32_t var_Q = 4;
    const uint32_t var_R_rtt = 4;
    const uint32_t var_Q_rtt = 4;

    bool initPackets;
    /** Create and return a OrbtcpStateVariables object. */
    virtual TcpStateVariables *createStateVariables() override
    {
        return new LeoccStateVariables();
    }

    virtual void initialize() override;

    /** Utility function to recalculate ssthresh */
    virtual void recalculateSlowStartThreshold();

    /** Redefine what should happen on retransmission */
    virtual void processRexmitTimer(TcpEventCode& event) override;

    virtual void rttMeasurementComplete(simtime_t tSent, simtime_t tAcked) override;

    virtual void updateModelAndState();

    virtual void updateControlParameters();

    virtual void updateBottleneckBandwidth();

    virtual void updateAckAggregation();

    virtual void checkCyclePhase();

    virtual void checkFullPipe();

    virtual void checkDrain();

    virtual void updateRTprop();

    virtual void checkProbeRTT();

    virtual void updateRound();

    virtual bool isNextCyclePhase();

    virtual void advanceCyclePhase();

    virtual uint32_t inFlight(double gain);

    virtual void enterDrain();

    virtual void enterProbeBW();

    virtual void setLeoccState(LeoccMode_t mode);

    virtual void enterProbeRTT();

    virtual void handleProbeRTT();

    virtual void saveCwnd();

    virtual void restoreCwnd();

    virtual void exitProbeRTT();

    virtual void enterStartup();

    virtual void setPacingRate(double gain);

    virtual void setSendQuantum();

    virtual void setCwnd();

    virtual void initPacingRate();

    virtual bool modulateCwndForRecovery();

    virtual void updateTargetCwnd();

    virtual uint32_t ackAggregationCwnd();

    virtual void modulateCwndForProbeRTT();

    virtual void initRoundCounting();

    virtual void initFullPipe();

    virtual uint32_t probeRttCwnd();

    virtual void leoccMain();
  public:
    /** Constructor */
    LeoccFlavour();

    virtual void established(bool active) override;

    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck() override;

    virtual void setFirstSentTime(simtime_t time) { state->firstSentTime = time.dbl();};
    virtual void setDeliveredTime(simtime_t time) { state->deliveredTime = time.dbl();};

    virtual double getFirstSentTime() { return state->firstSentTime;};
    virtual double getDeliveredTime() { return state->deliveredTime;};

    };

} // namespace tcp
} // namespace inet

#endif

