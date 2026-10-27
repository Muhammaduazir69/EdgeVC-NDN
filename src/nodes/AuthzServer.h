#ifndef __NDNPREENCRYPTION_AUTHZSERVER_H_
#define __NDNPREENCRYPTION_AUTHZSERVER_H_

#include <omnetpp.h>
#include <deque>
#include <map>

#include "NodeCommon.h"
#include "../security/AccessPolicy.h"
#include "../security/CryptoEngine.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * Remote authorization service used by the two baselines.
 *  mode = "pdp":       central policy decision point of a XACML-style ABAC
 *                      deployment. Identity updates apply on receipt.
 *  mode = "validator": one endorsing peer of a permissioned ledger
 *                      (Fabric-like execute-order-validate). Identity
 *                      transactions are buffered and become visible only at
 *                      the next block commit (every blockInterval).
 * Both serve AuthzRequests through a single FIFO CPU whose service time is
 * the calibrated cost of: verify the Interest signature, evaluate the
 * shared policy, sign the decision.
 */
class AuthzServer : public cSimpleModule {
  public:
    const Bytes &getSigningPublicKey() const { return key.publicKey; }

  protected:
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    struct Identity {
        Bytes signingPk;
        std::string role, unit, sealedRk;
        int clearance = 1;
        int status = 0;
    };
    void serve(AuthzRequest *req);
    void applyUpdate(IdentityUpdate *u);
    void sendCtrl(CtrlPacket *pkt, int dst);
    bool down() const;

    std::string mode;
    Ed25519KeyPair key;
    double blockInterval = 2.0;
    double cpuFactor = 1.0;
    double failAt = -1, recoverAt = -1;
    std::map<std::string, Identity> ledger;
    std::vector<IdentityUpdate *> mempool;
    // Block-event peer (lowest-id validator) pushes invalidations at commit
    // when the issuer runs the "+push" baseline.
    bool eventPeer = false;
    std::vector<int> edgeRouters;
    void emitBlockEvent(IdentityUpdate *u);
    std::map<int, int> routes;
    GateTx tx;
    simtime_t cpuFree = 0;
    double busy = 0;
    long served = 0, droppedWhileDown = 0;
    cMessage *blockTimer = nullptr;
};

} // namespace ndnpreencryption

#endif
