#ifndef __NDNPREENCRYPTION_SIMULATIONMANAGER_H_
#define __NDNPREENCRYPTION_SIMULATIONMANAGER_H_

#include <omnetpp.h>
#include "MetricsCollector.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * Run bookkeeping: resets the metrics sink and loads the calibrated crypto
 * cost table before any node initializes (stage 0, first submodule), and
 * exports the run's CSV files once every module has run finish().
 */
class SimulationManager : public cSimpleModule, public cISimulationLifecycleListener {
  protected:
    virtual int numInitStages() const override { return 1; }
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override { delete msg; }
    virtual void lifecycleEvent(SimulationLifecycleEventType type, cObject *details) override;
    virtual void listenerRemoved() override {}
  public:
    virtual ~SimulationManager();
  private:
    bool registered = false;
};

} // namespace ndnpreencryption

#endif
