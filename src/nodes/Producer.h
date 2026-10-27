#ifndef __NDNPREENCRYPTION_PRODUCER_H_
#define __NDNPREENCRYPTION_PRODUCER_H_

#include <omnetpp.h>
#include <map>

#include "NodeCommon.h"
#include "../security/EnforcementEngine.h"
#include "../utils/FHIRGenerator.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * EHR repository. Each content object is encrypted once (AES-256-GCM under
 * a fresh DEK), the DEK is encapsulated under the data owner's PRE key, and
 * the result is signed. The Data packet is identical for every consumer,
 * so routers may cache and aggregate it.
 *
 * framework = "didvc_producer" is the ablation in which the producer itself
 * is the enforcement point: names carry a per-consumer suffix (no sharing
 * of cached Data), the full presentation travels end to end, and the
 * producer re-encapsulates for the requester.
 */
class Producer : public cSimpleModule {
  public:
    const Bytes &getSigningPublicKey() const { return key.publicKey; }

  protected:
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    struct Job { cPacket *pkt; int gate; };
    DataPacket *contentFor(const std::string &baseName, double &cost);
    void onInterest(InterestPacket *ip, int gate);
    void onStatus(cPacket *p);
    static std::string stripRecipient(const std::string &name);

    std::string framework, prefix;
    bool secure = true;
    double cpuFactor = 1.0;
    Ed25519KeyPair key;
    Bytes ownerPk;
    FHIRGenerator fhir;
    std::map<std::string, DataPacket *> repo;
    GateTx tx;
    simtime_t cpuFree = 0;
    long served = 0, generated = 0, denied = 0;

    // Ablation-only enforcement state.
    EnforcementEngine engine;
    StatusList status;
    Bytes issuerPk;
};

} // namespace ndnpreencryption

#endif
