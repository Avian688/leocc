//
// Linux-faithful LeoCC flavour for OMNeT++.
//

#ifndef TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOURFIXED_H_
#define TRANSPORTLAYER_LEOCC_FLAVOURS_LEOCCFLAVOURFIXED_H_

#include "LeoccFlavour.h"

namespace inet {
namespace tcp {

class LeoccFlavourFixed : public LeoccFlavour
{
  protected:
    virtual void handleProbeRTT() override;
};

} // namespace tcp
} // namespace inet

#endif
