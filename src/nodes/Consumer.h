#ifndef __NDNPREENCRYPTION_CONSUMER_H_
#define __NDNPREENCRYPTION_CONSUMER_H_

#include <omnetpp.h>
#include <deque>
#include <set>
#include <map>
#include <string>
#include <vector>

#include "NodeCommon.h"
#include "../security/AccessPolicy.h"
#include "../security/CryptoEngine.h"
#include "../security/DID.h"
#include "../security/UmbralPRE.h"
#include "../security/VC.h"
#include "../utils/FHIRGenerator.h"

using namespace omnetpp;

namespace ndnpreencryption {

class Issuer;

/**
 * Clinician endpoint. Generates a Poisson stream of Interests over a
 * shared FHIR catalog (a share of requests follows the clinician's own
 * permitted subset, the rest are Zipf draws over the whole catalog), signs
 * each Interest, presents its credential in the framework's way, and
 * decrypts the returned Data with its PRE key. With attackType != "none"
 * the module is an adversary instead (replay, forged or stolen credential,
 * DID spoofing, claim tampering, credential-less probing).
 */
class Consumer : public cSimpleModule {
  public:
    // Eavesdropping model for the replay / stolen-credential adversaries.
    const InterestPacket *peekLastInterest() const { return lastSent; }
    const std::string &getVcJson() const { return vcJson; }
    const std::string &getDid() const { return did; }
    const std::string &getDidDocJson() const { return didDocJson; }

  protected:
    virtual int numInitStages() const override { return 2; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    // part: 0 ordinary request, 1 content half and 2 key half of a key-split request
    struct Pending { long rec; simtime_t sent; double lifetime; int nonce; std::string base; bool bg; int part; };
    struct KeySplit { DataPacket *content = nullptr, *key = nullptr; bool done = false; };
    void deliver(const std::vector<Pending> &waiting, DataPacket *content, DataPacket *keySrc);
    void touchLocal(const std::string &name);

    void enroll();
    void onIssueResponse(VCIssueResponse *r);
    void generateInterest();
    void generateAttack();
    InterestPacket *buildInterest(const std::string &name, bool breakGlass, bool forceFull);
    void signInto(InterestPacket *ip, const Bytes &sk, const std::string &fp);
    void onData(DataPacket *d);
    void onNack(NACKPacket *n);
    void sweepTimeouts();
    std::string drawName(bool preferred);
    void sendAfterCpu(cPacket *p, double cost);
    long track(InterestPacket *ip, const std::string &name, bool expected, bool attack,
               const std::string &attackType);

    std::string framework, role, unit, organization, attackType;
    int clearance = 1;
    double rate = 4, preferredShare = 0.85, zipf = 0.8, breakGlassRate = 0, lifetime = 4;
    double attackRate = 0, cpuFactor = 1, presentationRefresh = 0;
    bool compact = true, secure = true, needFull = true;
    simtime_t lastFull = -1;

    Ed25519KeyPair sigKey;
    PreKeyPair preKey;
    std::string did, didDocJson, didDocFp, vcJson, vcId;
    bool enrolled = false;
    int issuerId = -1;
    Issuer *issuer = nullptr;
    Bytes producerPk;
    Consumer *victim = nullptr;

    std::vector<std::string> catalog, preferred;
    std::vector<double> cdfAll, cdfPref;
    FHIRGenerator fhir;
    std::map<std::string, std::deque<Pending>> pending;
    std::map<long, KeySplit> splits;
    std::deque<std::string> localLru;          // client-side record cache (names)
    std::set<std::string> localSet;
    int clientCacheSize = 0;
    bool stopped = false;                      // credential revoked: the clinician stops
    bool stopOnRevocation = true;              // false: persistent insider keeps requesting
    simtime_t backoffUntil = 0;                // credential suspended: probe every 30 s
    InterestPacket *lastSent = nullptr;

    GateTx tx;
    simtime_t cpuFree = 0;
    cMessage *reqTimer = nullptr, *atkTimer = nullptr, *sweepTimer = nullptr, *enrollRetry = nullptr;
    long sent = 0, dataOk = 0, nacks = 0, timeouts = 0, decryptFail = 0;
};

} // namespace ndnpreencryption

#endif
