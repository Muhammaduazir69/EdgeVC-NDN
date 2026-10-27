#ifndef __NDNPREENCRYPTION_ISSUER_H_
#define __NDNPREENCRYPTION_ISSUER_H_

#include <omnetpp.h>
#include <map>
#include <set>
#include <vector>

#include "NodeCommon.h"
#include "../security/CryptoEngine.h"
#include "../security/StatusList.h"
#include "../security/UmbralPRE.h"
#include "../security/VC.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * Hospital credential authority and data owner.
 *  - enrolls clinicians: issues a VC (didvc) or pushes the identity record
 *    to the PDP (abac) or the validator set (scbac);
 *  - holds the data-owner PRE key pair and derives rk(owner -> holder);
 *  - runs the revocation / suspension workload and propagates each change
 *    in the way its framework prescribes;
 *  - for didvc, signs the status list (deltas on change, periodic
 *    snapshots) and answers pull requests.
 */
class Issuer : public cSimpleModule {
  public:
    const Bytes &getSigningPublicKey() const { return signingKey.publicKey; }
    const std::string &getDid() const { return issuerDid; }
    const Bytes &getOwnerPrePublicKey() const { return ownerPre.pk; }
    const Bytes &getSealKey() const { return sealKey; }
    std::string getStatusListName() const { return statusListName; }
    // Ground-truth oracle for the consumers (not a protocol path).
    bool holderEnrolledAndActive(const std::string &did) const;

  protected:
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    struct RosterEntry { std::string role, unit; int clearance = 1; };
    bool down() const;
    struct Holder {
        int consumerModule = -1;
        std::string role, unit;
        int clearance = 1;
        Bytes signingPk, prePk;
        std::string sealedRk;
        CredStatus status = CredStatus::ACTIVE;
        std::vector<int> indices;
        bool enrolled = false;
    };

    void onIssueRequest(VCIssueRequest *req);
    void changeStatus(const std::string &did, CredStatus st, const char *reason);
    void publishDelta(int index, CredStatus st);
    void publishSnapshot();
    void sendIdentityUpdates(const std::string &did, const Holder &h);
    void floodOut(cPacket *pkt);
    void sendCtrl(CtrlPacket *pkt, int dst);
    std::string pickActiveHolder();

    std::string framework;
    std::string issuerDid;
    Ed25519KeyPair signingKey;
    PreKeyPair ownerPre;
    Bytes sealKey;
    std::string statusListName;
    StatusList list;
    std::string lastSnapshotJson;

    double snapshotInterval = 30, vcValidity = 86400, reactivationDelay = 60;
    double revocationRate = 0, suspensionRate = 0;
    std::vector<double> scheduledRevocations;
    bool pushStatus = true;
    long seq = 0;
    int nextIndex = 0;
    long issued = 0, refused = 0, deltas = 0, snapshots = 0;
    long revocations = 0, suspensions = 0, reactivations = 0;

    std::map<std::string, Holder> holders;
    std::vector<int> authzTargets;   // PDP or validators
    std::vector<int> edgeRouters;    // targets of pushed invalidations
    bool pushInvalidation = false;
    double failAt = -1, recoverAt = -1;
    // Staff roster held by the hospital's HR system: enrollment is bound to
    // an identity-proofed staff record, and attributes come from the roster,
    // never from the request.
    std::map<int, RosterEntry> roster;
    std::set<int> insiderAttackers;   // enrolled adversaries: kept out of the revocation workload
    std::map<int, int> routes;
    GateTx tx;

    cMessage *snapshotTimer = nullptr, *revokeTimer = nullptr,
             *suspendTimer = nullptr, *scheduledTimer = nullptr;
    struct Pending { std::string did; simtime_t when; };
    std::vector<Pending> reactivationsDue;
    cMessage *reactivateTimer = nullptr;
    cMessage *recoverTimer = nullptr;
};

} // namespace ndnpreencryption

#endif
