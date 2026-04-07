//
// Comparison-only LeoCC flavour with proposed fixes.
// This file is intentionally not referenced by the build or NED files.
//

#ifndef TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOURFIXED_H_
#define TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOURFIXED_H_

#include "LeoccFlavour.h"

namespace inet {
namespace tcp {

class LeoccFlavourFixed : public LeoccFlavour
{
  protected:
    bool previousGlobalReconfigurationTrigger = false;

    virtual void updateBottleneckBandwidth() override;
    virtual void handleProbeRTT() override;
    virtual void leoccMain() override;
};

} // namespace tcp
} // namespace inet

#endif
