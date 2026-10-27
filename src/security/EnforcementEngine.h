#ifndef __NDNPREENCRYPTION_ENFORCEMENTENGINE_H_
#define __NDNPREENCRYPTION_ENFORCEMENTENGINE_H_

#include <deque>
#include <list>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "AccessPolicy.h"
#include "CryptoEngine.h"
#include "DID.h"
#include "StatusList.h"
#include "UmbralPRE.h"
#include "VC.h"

namespace ndnpreencryption {

// Verification stages. Each stage has a calibrated CPU cost (CostModel);
// the simulated decision delay is the sum of the stages actually executed,
// so an Interest rejected at stage 1 costs less than one granted at stage 5.
enum class Stage : int {
    DID_PARSE_THUMBPRINT = 0,  // parse DID document, SHA-256 JWK thumbprint
    INTEREST_SIG_VERIFY,       // Ed25519 verify of the Interest signature
    VC_PARSE_VERIFY,           // parse VC, canonicalize, Ed25519 verify
    CLAIMS_STATUS_POLICY,      // subject binding, validity, status, policy
    REKEY_UNSEAL,              // AES-256-GCM open of the sealed rk
    SESSION_LOOKUP,            // compact presentation: session + nonce cache
    PRE_REENCAPSULATE,         // capsule check + two scalar multiplications
    DECISION_SIGN,             // PDP / validator signs its decision
    DECISION_VERIFY,           // PEP verifies one PDP / validator signature
    POLICY_ONLY,               // PDP / validator policy lookup
    COUNT
};

const char *stageName(Stage s);

enum class Verdict : int {
    GRANT = 0,
    DENY_SIGNATURE = 2,
    DENY_SUSPENDED = 3,
    DENY_REVOKED = 4,
    DENY_EXPIRED = 5,
    NEED_PRESENTATION = 6,
    DENY_REPLAY = 8,
    DENY_POLICY = 9,
    DENY_FORGED = 10,          // issuer not trusted / VC signature invalid
    DENY_BINDING = 11,         // DID thumbprint or VC subject mismatch
    DENY_NO_CREDENTIAL = 12,   // unsigned Interest at a remote-authority PEP
};

int verdictToNackReason(Verdict v);
const char *verdictName(Verdict v);

struct InterestView {
    std::string name;
    std::string requesterId;
    std::string nonceHex;
    int lifetimeMs = 4000;
    long long signingTs = 0;
    std::string signatureB64;
    int presentationMode = 0;
    std::string didDocJson;
    std::string vcJson;
    std::string vcId;
    bool breakGlass = false;
};

struct Decision {
    Verdict verdict = Verdict::DENY_POLICY;
    std::string rule;              // matching policy rule when granted
    PreReKey rk;
    double modeledCpu = 0;         // sum of calibrated stage costs (s)
    double measuredCpu = 0;        // wall clock of the real calls (s)
    int stages = 0;                // number of stages executed
    std::string subjectRole, subjectUnit;
    int statusIndex = -1;
};

// Canonical Interest signing input shared by consumer and verifiers.
std::string interestSigningInput(const std::string &name, const std::string &requesterId,
                                 const std::string &nonceHex, int lifetimeMs,
                                 long long ts, const std::string &vcId,
                                 bool breakGlass, const std::string &keyFingerprint);

/**
 * Calibrated per-stage CPU costs. Measured once per process by running the
 * real code paths 400 times on representative inputs and taking the median.
 * A per-node speed factor scales them (1.0 = host CPU).
 */
class CostModel {
  public:
    static CostModel &instance();
    double cost(Stage s) const { return costs[(int)s]; }
    double aesPerKiB() const { return aesKiB; }
    double edSign() const { return sign; }
    double edVerify() const { return verify; }
    double preEncapsulate() const { return encap; }
    double preDecapsulate() const { return decap; }
    void calibrate();
    bool calibrated() const { return done; }
    // Reproducibility: load a previously saved calibration if the file
    // exists, otherwise calibrate now and save it. All runs of a campaign
    // then share bit-identical stage costs.
    void loadOrCalibrate(const std::string &path);
    std::string report() const;
  private:
    double costs[(int)Stage::COUNT] = {0};
    double aesKiB = 0, sign = 0, verify = 0, encap = 0, decap = 0;
    bool done = false;
};

/**
 * DID+VC enforcement engine of one edge node: verifies presentations,
 * keeps verified sessions for compact presentations, and a nonce cache
 * against replay. Purely computational; the caller turns modeledCpu into
 * simulated delay.
 */
class EnforcementEngine {
  public:
    void configure(const std::string &issuerDid, const Bytes &issuerPk,
                   const Bytes &sealKey, const StatusList *status,
                   size_t sessionCapacity, double replayWindowSec);

    Decision evaluate(const InterestView &iv, long long nowEpoch);

    size_t sessions() const { return sessionIndex.size(); }
    long sessionEvictions() const { return evictions; }

    // Seal/unseal helpers shared with the issuer, PDP and validators.
    static std::string sealReKey(const Bytes &sealKey, const PreReKey &rk);
    static bool unsealReKey(const Bytes &sealKey, const std::string &sealed, PreReKey &rk);

  private:
    struct Session {
        std::string did;
        Bytes signingPk;
        std::string keyFingerprint;
        std::string vcId;
        SubjectAttrs subject;
        long long validFrom = 0, validUntil = 0;
        int statusIndex = -1;
        PreReKey rk;
    };

    bool replaySeen(const std::string &requester, const std::string &nonce,
                    long long ts, long long now);
    void storeSession(const Session &s);

    std::string issuerDid;
    Bytes issuerPk;
    Bytes sealKey;
    const StatusList *status = nullptr;
    size_t capacity = 1024;
    double replayWindow = 30.0;

    std::list<std::string> lru;                       // most recent first
    std::unordered_map<std::string, std::pair<Session, std::list<std::string>::iterator>> sessionIndex;
    long evictions = 0;

    std::unordered_set<std::string> nonceSet;
    std::deque<std::pair<long long, std::string>> nonceAge;
};

} // namespace ndnpreencryption

#endif
