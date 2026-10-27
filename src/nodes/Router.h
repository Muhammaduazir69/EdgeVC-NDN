#ifndef __NDNPREENCRYPTION_ROUTER_H_
#define __NDNPREENCRYPTION_ROUTER_H_

#include <omnetpp.h>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "NodeCommon.h"
#include "../security/EnforcementEngine.h"
#include "../tables/ContentStore.h"
#include "../tables/FIB.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * NDN forwarder. A router with at least one consumer-facing face is an
 * edge router and acts as the enforcement point and PRE proxy for those
 * faces; every other face is handled as plain NDN (CS, PIT aggregation,
 * FIB). The access-control framework changes only how the edge reaches
 * its decision:
 *   didvc  local verification of the in-band DID/VC presentation against
 *          the replicated status list (full or compact presentation);
 *   abac   query to a central PDP (optional decision cache);
 *   scbac  endorsements from a 2f+1 quorum of validators (optional cache);
 *   none / didvc_producer: no enforcement at the edge.
 * After a grant, the edge serves the consumer-agnostic Data from its CS or
 * fetches it once upstream, then re-encapsulates the PRE capsule for each
 * granted requester.
 */
class Router : public cSimpleModule {
  protected:
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    // Context of one consumer Interest at the edge.
    struct Ctx {
        int face = -1;
        std::string name, requester;
        int nonce = 0;
        bool breakGlass = false, attack = false;
        int origin = -1;
        simtime_t arrival;
        PreReKey rk;
        InterestView iv;
        double lifetime = 4.0;
    };
    struct PitEntry {
        simtime_t expires;
        simtime_t lastForwarded;
        std::vector<Ctx> consumers;      // granted consumer requests (edge)
        // plain downstream faces -> (PIT token to echo, requesting consumer)
        std::map<int, std::vector<std::pair<int, int>>> faces;
        int prefetchFor = -1;            // speculative fetch on behalf of this consumer
    };
    struct PendingAuthz {
        Ctx ctx;
        int grants = 0, denies = 0, lastDeny = 2;
        std::string sealedRk, signingPk;
        double verifyCost = 0;
        cMessage *timeout = nullptr;
        bool done = false;
        simtime_t sentAt;
    };
    struct CachedDecision { bool granted; int denyReason; PreReKey rk; simtime_t expires; };
    struct CachedIdentity { Bytes pk; simtime_t expires; };

    class Job : public cMessage {
      public:
        std::function<void()> fn;
        Job() : cMessage("job") {}
    };

    // Work runs on a single FIFO CPU; `cost` seconds after it can start.
    void runAfter(double cost, std::function<void()> fn);
    void runAt(simtime_t t, std::function<void()> fn);

    void onInterest(InterestPacket *ip, int face);
    void transitInterest(InterestPacket *ip, int face);
    void enforce(InterestPacket *ip, int face);
    void afterDecision(Ctx ctx, int verdictCode, const std::string &rule, double cpu,
                       double measured, bool dcHit, int nackReason);
    void serveGranted(const Ctx &ctx, double extraCost);
    void forwardUpstream(const std::string &name, double lifetime, InterestPacket *orig);
    void sendNack(int face, const std::string &name, int nonce, int reason);
    void onData(DataPacket *d);
    void onNack(NACKPacket *n);
    DataPacket *personalize(const DataPacket *tmpl, const Ctx &c, double &cost);

    void queryAuthz(Ctx ctx);
    void onAuthzResponse(AuthzResponse *r);
    void authzTimeout(int64_t reqId);
    bool replaySeen(const std::string &req, const std::string &nonce, long long ts, long long now);

    void onDelta(VCListDeltaPacket *p, int face);
    void onSnapshot(VCListSnapshotPacket *p, int face);
    void onSyncRequest(VCListSyncRequest *r);
    void onSyncResponse(StatusSyncResponse *r);
    bool applyDeltaJson(const std::string &json, int fromNeighbour);
    void flood(cPacket *p, int except);
    void sendCtrl(CtrlPacket *p, int dst);
    void purgePit();

    std::string framework;
    bool enforcing = false, isEdge = false;
    double fwdDelay = 50e-6, cpuFactor = 1.0, authzTimeoutSec = 2.0, dcTtl = 0;
    int pitSize = 4000;
    int defaultCtrlFace = -1;
    double suppression = 0.25;   // NFD-style retransmission suppression interval
    std::vector<bool> consumerFace;
    std::vector<int> faceNeighbourId;
    ContentStore *cs = nullptr;
    FIB *fib = nullptr;
    int rr = 0;
    std::unordered_map<std::string, PitEntry> pit;
    std::map<int, int> routes;
    GateTx tx;
    simtime_t cpuFree = 0;
    double cpuBusy = 0;

    // didvc
    EnforcementEngine engine;
    StatusList status;
    Bytes issuerPk;
    int issuerId = -1;
    Ed25519KeyPair auditKey;
    std::set<int> floodedDeltas;
    // Issue time of every verified delta, by version. The edge counts itself
    // fresh only up to the issue time of the newest version it has applied
    // contiguously (or of a snapshot it is at least as new as): a buffered
    // delta behind a gap proves nothing about the missing versions.
    std::map<int, long long> versionIssuedAt;
    void refreshFromVersion();
    void refloodDelta(const std::string &json, int version, int except);
    long long freshAt = 0;          // issuedAt of the newest verified status update
    double statusMaxAge = 0;        // fail closed when freshAt is older than this (0 = never)
    std::set<double> floodedSnapshots;
    std::string storedSnapshot;
    std::map<int, std::string> storedDeltas;
    bool syncInFlight = false;
    bool pullMode = false;
    double pullInterval = 10;
    cMessage *pullTimer = nullptr;
    cMessage *beaconTimer = nullptr;
    double beaconInterval = 1.0;

    // abac / scbac
    std::vector<int> authzServers;
    int quorum = 1;
    int64_t nextReq = 1;
    std::map<int64_t, PendingAuthz> pending;
    // Last pushed invalidation per holder: a decision for a request sent
    // before it may predate the status change and is never cached.
    std::map<std::string, simtime_t> invalidatedAt;
    bool speculativeFetch = false;
    std::map<std::string, CachedDecision> decisionCache;
    std::map<std::string, CachedIdentity> identityCache;
    std::unordered_set<std::string> nonceSet;
    std::deque<std::pair<long long, std::string>> nonceAge;
    double replayWindow = 30;
    Bytes sealKey;

    cMessage *purgeTimer = nullptr;
    long csHits = 0, csMisses = 0, granted = 0, deniedCount = 0, authzSent = 0;
};

} // namespace ndnpreencryption

#endif
