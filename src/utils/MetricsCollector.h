#ifndef __NDNPREENCRYPTION_METRICSCOLLECTOR_H_
#define __NDNPREENCRYPTION_METRICSCOLLECTOR_H_

#include <omnetpp.h>
#include <map>
#include <string>
#include <vector>

using namespace omnetpp;

namespace ndnpreencryption {

// Byte classes counted on every link transmission (a packet crossing h
// links is counted h times).
enum class ByteClass : int {
    INTEREST_BASE = 0,     // name, nonce, lifetime
    INTEREST_AUTH,         // requester id, timestamp, 128-bit nonce, signature
    INTEREST_CREDENTIAL,   // DID document, VC, compact reference
    DATA,                  // name and record (ciphertext of the same length)
    DATA_PROTECTION,       // AEAD IV/tag, PRE capsule, re-encapsulation, producer signature
    NACK,
    AUTHZ,                 // PEP <-> PDP query and decision
    ENDORSE,               // PEP <-> validator endorsements
    VC_ISSUE,              // issuance / enrollment
    IDENTITY_UPDATE,       // issuer -> PDP / validators
    STATUS_DELTA,
    STATUS_SNAPSHOT,
    STATUS_SYNC,
    AUDIT,
    COUNT
};

const char *byteClassName(ByteClass c);

/**
 * Per-run measurement sink. Every number exported here is an aggregate of
 * events observed in the running simulation; nothing is synthesized. The
 * SimulationManager resets it at initialization and exports at finish.
 */
class MetricsCollector {
  public:
    struct InterestRecord {
        long id = 0;
        int consumer = -1;
        std::string requester;     // holder DID
        bool holderActive = true;  // authoritative status at send time
        std::string role, unit;
        double tSend = 0;
        std::string name;
        std::string sensitivity;
        bool expected = false;     // ground truth: policy AND authoritative status
        bool attack = false;
        std::string attackType;
        bool breakGlass = false;
        bool bgScope = false;      // flagged, denied by routine rules, permitted by the BG rule
        bool bgUnqualified = false;// flagged, not permitted even by the BG rule
        int presentation = 0;
        int interestBytes = 0;
        // outcome
        int outcome = -1;          // 0 data, 1 nack, 2 timeout, -1 pending
        int nackReason = -1;
        double tResp = -1;
        bool decryptOk = false;
        int plainBytes = 0;
    };

    struct DecisionRecord {
        double t = 0;
        int node = -1;
        std::string requester;
        std::string name;
        int verdict = 0;           // Verdict enum value
        double decisionDelay = 0;  // arrival -> decision (simulated)
        double modeledCpu = 0;
        double measuredCpu = 0;
        bool csHit = false;
        bool decisionCacheHit = false;
        bool breakGlass = false;
        bool attack = false;
        std::string rule;
        bool staleGrant = false;   // granted while authoritatively revoked/suspended
    };

    static MetricsCollector *getInstance();
    void reset(const std::string &framework, double warmup);

    // Interests (consumer side).
    long newInterest(const InterestRecord &r);
    void interestOutcome(long id, int outcome, int nackReason, double tResp,
                         bool decryptOk, int plainBytes);
    // Decisions (enforcement side).
    void recordDecision(const DecisionRecord &d);
    // Bytes on links.
    void recordTx(ByteClass c, long bytes);
    // Cache counters at enforcement points and at transit routers.
    void recordEdgeCs(bool hit) { if (hit) edgeCsHits++; else edgeCsMisses++; }
    void recordEdgeCsCross(bool cross) { if (cross) edgeCsCross++; else edgeCsSelf++; }
    void recordLocalHit() { if (simTime().dbl() >= warmup) localHits++; }
    void recordTransitCs(bool hit) { if (hit) transitCsHits++; else transitCsMisses++; }
    void recordDecisionCache(bool hit) { if (hit) dcHits++; else dcMisses++; }
    void recordReencapsulation(double modeled) { reencCount++; reencSum += modeled; }
    void auditSent() { if (simTime().dbl() >= warmup) auditsSent++; }
    void auditReceived(double latency) { if (simTime().dbl() >= warmup) { auditsRecv++; auditLatency.push_back(latency); } }
    void auditRejected() { if (simTime().dbl() >= warmup) auditsRejected++; }
    // Authorization service load.
    void recordServiceBusy(int node, double busySeconds, long served);

    // Credential lifecycle (authoritative, from the issuer).
    void lifecycle(const std::string &requester, int statusIndex, int newStatus, double t);
    bool isAuthoritativelyActive(const std::string &requester) const;
    // Propagation: an enforcement-relevant node applied state version v.
    void stateApplied(int node, long version, double t);
    void statePublished(long version, double t, const std::string &kind);

    void setMeta(const std::string &k, const std::string &v) { meta[k] = v; }
    void exportAll(const std::string &prefix, bool detailed);

  private:
    MetricsCollector() = default;
    static MetricsCollector *inst;

    std::string framework;
    double warmup = 0;
    std::map<std::string, std::string> meta;

    std::vector<InterestRecord> interests;
    std::vector<DecisionRecord> decisions;
    long linkBytes[(int)ByteClass::COUNT] = {0};
    long linkPkts[(int)ByteClass::COUNT] = {0};
    long edgeCsHits = 0, edgeCsMisses = 0, transitCsHits = 0, transitCsMisses = 0;
    long edgeCsCross = 0, edgeCsSelf = 0, localHits = 0;
    long dcHits = 0, dcMisses = 0;
    long reencCount = 0;
    long auditsSent = 0, auditsRecv = 0, auditsRejected = 0;
    std::vector<double> auditLatency;
    double reencSum = 0;
    std::map<int, std::pair<double, long>> serviceLoad;

    struct Interval { int statusIndex; int status; double tStart; double tEnd; double lastStale; long staleGrants; };
    std::map<std::string, std::vector<Interval>> lifecycleByRequester;
    std::map<long, double> publishTime;
    std::map<long, std::string> publishKind;
    std::map<long, std::map<int, double>> applyTime;
};

} // namespace ndnpreencryption

#endif
