#include "Router.h"

#include <queue>
#include <sstream>

#include "AuthzServer.h"
#include "Issuer.h"
#include "../utils/Json.h"

namespace ndnpreencryption {

Define_Module(Router);

namespace {
std::map<int, Bytes> gServerKeys;   // trust anchors of PDP/validators, per run
}
std::map<int, Bytes> gAuditKeys;    // edge audit-signing keys, known to the issuer

void Router::initialize(int stage) {
    if (stage == 0) {
        framework = par("framework").stdstringValue();
        fwdDelay = par("forwardingDelay").doubleValue();
        cpuFactor = par("cpuFactor").doubleValue();
        authzTimeoutSec = par("authzTimeout").doubleValue();
        dcTtl = par("decisionCacheTtl").doubleValue();
        speculativeFetch = par("speculativeFetch").boolValue();
        pitSize = par("pitSize").intValue();
        suppression = par("suppressionInterval").doubleValue();
        replayWindow = par("replayWindow").doubleValue();
        pullMode = par("statusDissemination").stdstringValue() == "pull";
        pullInterval = par("pullInterval").doubleValue();
        cs = new ContentStore(par("csSize").intValue());
        fib = new FIB(64);
        tx.init(this, "port", par("priorityQueueing").boolValue());
        return;
    }

    int n = gateSize("port");
    consumerFace.assign(n, false);
    faceNeighbourId.assign(n, -1);
    int cStart = par("consumerFaceStart").intValue();
    for (int i = 0; i < n; i++) {
        cModule *p = peerOfGate(this, i);
        faceNeighbourId[i] = p ? p->getId() : -1;
        bool isC = cStart >= 0 ? i >= cStart : isConsumerModule(p);
        if (isC) { consumerFace[i] = true; isEdge = true; }
    }
    defaultCtrlFace = par("defaultCtrlFace").intValue();
    enforcing = isEdge && (framework == "didvc" || framework == "abac" || framework == "scbac");

    // FIB: the face(s) on a shortest router path toward the producer, or the
    // configured faces when the neighbours sit behind UDP faces.
    std::string upFaces = par("upstreamFaces").stdstringValue();
    std::vector<cModule *> producers = upFaces.empty() ? findModulesByType(this, "Producer")
                                                       : std::vector<cModule *>();
    if (!upFaces.empty()) {
        std::istringstream us(upFaces);
        int f;
        while (us >> f) fib->addRoute(par("contentPrefix").stringValue(), f, 1.0);
    }
    if (!producers.empty()) {
        cModule *prod = producers.front();
        std::map<cModule *, int> firstFace;
        std::queue<cModule *> q;
        std::set<cModule *> seen{this};
        int bestDepth = -1;
        std::map<cModule *, int> depth;
        for (int i = 0; i < n; i++) {
            cModule *p = peerOfGate(this, i);
            if (!p || consumerFace[i]) continue;
            if (p == prod) { fib->addRoute(par("contentPrefix").stringValue(), i, 1.0); bestDepth = 0; continue; }
            if (!isRouterModule(p) || seen.count(p)) continue;
            seen.insert(p); firstFace[p] = i; depth[p] = 1; q.push(p);
        }
        while (bestDepth < 0 && !q.empty()) {
            cModule *m = q.front(); q.pop();
            for (int j = 0; j < m->gateSize("port"); j++) {
                cModule *p = peerOfGate(m, j);
                if (!p) continue;
                if (p == prod) {
                    fib->addRoute(par("contentPrefix").stringValue(), firstFace[m], 1.0);
                    bestDepth = depth[m];
                    continue;
                }
                if (!isRouterModule(p) || seen.count(p)) continue;
                seen.insert(p); firstFace[p] = firstFace[m]; depth[p] = depth[m] + 1; q.push(p);
            }
        }
    }
    routes = buildControlRoutes(this);
    {
        // Static control routes "modulePath=face, ..." (UDP faces).
        std::istringstream cs(par("ctrlRoutes").stdstringValue());
        std::string tok;
        while (std::getline(cs, tok, ',')) {
            size_t eq = tok.find('=');
            if (eq == std::string::npos) continue;
            std::string path = tok.substr(0, eq);
            path.erase(0, path.find_first_not_of(' '));
            cModule *m = getModuleByPath(path.c_str());
            if (m) routes[m->getId()] = std::stoi(tok.substr(eq + 1));
        }
    }

    if (framework.rfind("didvc", 0) == 0) {
        auto *iss = check_and_cast<Issuer *>(getModuleByPath(par("issuerModulePath").stringValue()));
        issuerPk = iss->getSigningPublicKey();
        issuerId = iss->getId();
        statusMaxAge = par("statusMaxAge").doubleValue();
        freshAt = kSimEpochBase;      // the edge is provisioned with a current snapshot
        auditKey = CryptoEngine::generateEd25519KeyPair();
        gAuditKeys[getId()] = auditKey.publicKey;
        engine.configure(iss->getDid(), issuerPk, iss->getSealKey(), &status,
                         (size_t)par("sessionCapacity").intValue(), replayWindow);
        if (pullMode && isEdge) {
            pullTimer = new cMessage("pull");
            scheduleAt(uniform(0, pullInterval), pullTimer);
        }
        beaconInterval = par("statusBeacon").doubleValue();
        if (!pullMode && beaconInterval > 0) {
            beaconTimer = new cMessage("beacon");
            scheduleAt(uniform(0, beaconInterval), beaconTimer);
        }
    }
    if (framework == "abac" || framework == "scbac") {
        auto *iss = check_and_cast<Issuer *>(getModuleByPath(par("issuerModulePath").stringValue()));
        sealKey = iss->getSealKey();
        for (cModule *m : findModulesByType(this, "AuthzServer")) {
            std::string mode = m->par("mode").stdstringValue();
            if ((framework == "abac" && mode == "pdp") || (framework == "scbac" && mode == "validator")) {
                authzServers.push_back(m->getId());
                gServerKeys[m->getId()] = check_and_cast<AuthzServer *>(m)->getSigningPublicKey();
            }
        }
        int nv = (int)authzServers.size();
        int f = (nv - 1) / 3;
        quorum = framework == "abac" ? 1 : 2 * f + 1;
    }
    purgeTimer = new cMessage("purge");
    scheduleAt(1.0, purgeTimer);
}

// ------------------------------------------------------------------ CPU

void Router::runAfter(double cost, std::function<void()> fn) {
    simtime_t start = std::max(simTime(), cpuFree);
    cpuFree = start + cost;
    cpuBusy += cost;
    runAt(cpuFree, std::move(fn));
}

void Router::runAt(simtime_t t, std::function<void()> fn) {
    Job *j = new Job();
    j->fn = std::move(fn);
    scheduleAt(t, j);
}

// -------------------------------------------------------------- dispatch

void Router::handleMessage(cMessage *msg) {
    if (tx.handleTimer(msg)) return;
    bool redelivered = takeRedelivery(msg);
    if (auto j = dynamic_cast<Job *>(msg)) {
        auto fn = std::move(j->fn);
        delete j;
        fn();
        return;
    }
    if (msg == purgeTimer) {
        purgePit();
        scheduleAt(simTime() + 1.0, purgeTimer);
        return;
    }
    if (msg == beaconTimer) {
        // Anti-entropy: advertise our status-list version to every
        // infrastructure neighbour; whoever is behind pulls.
        for (int i = 0; i < tx.size(); i++) {
            if (consumerFace[i]) continue;
            cModule *p = peerOfGate(this, i);
            if (!p || !(isRouterModule(p) || p->getId() == issuerId)) continue;
            auto *b = new VCListSyncRequest("StatusBeacon");
            b->setSrcId(getId());
            b->setDstId(p->getId());
            b->setKnownVersion(status.version());
            b->setByteLength(24);
            tx.send(b, i);
        }
        scheduleAt(simTime() + beaconInterval, beaconTimer);
        return;
    }
    if (msg == pullTimer) {
        auto *r = new VCListSyncRequest("StatusPull");
        r->setSrcId(getId());
        r->setDstId(issuerId);
        r->setKnownVersion(status.version());
        r->setByteLength(32);
        sendCtrl(r, issuerId);
        scheduleAt(simTime() + pullInterval, pullTimer);
        return;
    }
    if (!redelivered && handleLinkLoss(this, msg)) return;
    int face = (!redelivered && msg->getArrivalGate()) ? msg->getArrivalGate()->getIndex() : -1;
    if (auto c = dynamic_cast<CtrlPacket *>(msg)) {
        if (face >= 0 && !routes.count(c->getSrcId())) routes[c->getSrcId()] = face;   // reverse-path learning
        if (c->getDstId() != getId()) {
            runAfter(fwdDelay, [this, c] { sendCtrl(c, c->getDstId()); });
            return;
        }
        if (auto r = dynamic_cast<AuthzResponse *>(msg)) {
            // Each signed decision is verified as it arrives, on the CPU.
            runAfter(cpuFactor * CostModel::instance().cost(Stage::DECISION_VERIFY),
                     [this, r] { onAuthzResponse(r); delete r; });
            return;
        }
        if (auto r = dynamic_cast<StatusSyncResponse *>(msg)) {
            int n = (int)Json::splitArrayElements(r->getDeltasJson()).size() +
                    (std::strlen(r->getSnapshotJson()) > 0 ? 1 : 0);
            runAfter(fwdDelay + n * cpuFactor * CostModel::instance().edVerify(),
                     [this, r] { onSyncResponse(r); delete r; });
            return;
        }
        if (auto u = dynamic_cast<IdentityUpdate *>(msg)) {
            // Pushed invalidation (C-ABAC/BC-AC "+push" baselines): drop every
            // cached decision and identity of this holder at once.
            std::string prefix = std::string(u->getUserId()) + "|";
            for (auto it = decisionCache.begin(); it != decisionCache.end();)
                if (it->first.compare(0, prefix.size(), prefix) == 0) it = decisionCache.erase(it); else ++it;
            identityCache.erase(u->getUserId());
            invalidatedAt[u->getUserId()] = simTime();
            if (isEdge) MetricsCollector::getInstance()->stateApplied(getId(), u->getSeq(), simTime().dbl());
            delete msg;
            return;
        }
        if (auto r = dynamic_cast<VCListSyncRequest *>(msg)) onSyncRequest(r);
        delete msg;
        return;
    }
    if (auto ip = dynamic_cast<InterestPacket *>(msg)) { onInterest(ip, face); return; }
    if (auto d = dynamic_cast<DataPacket *>(msg)) { onData(d); return; }
    if (auto nk = dynamic_cast<NACKPacket *>(msg)) { onNack(nk); return; }
    if (auto d = dynamic_cast<VCListDeltaPacket *>(msg)) { onDelta(d, face); return; }
    if (auto s = dynamic_cast<VCListSnapshotPacket *>(msg)) { onSnapshot(s, face); return; }
    delete msg;
}

// ------------------------------------------------------------- Interests

void Router::onInterest(InterestPacket *ip, int face) {
    if (consumerFace[face] && enforcing) enforce(ip, face);
    else transitInterest(ip, face);
}

void Router::transitInterest(InterestPacket *ip, int face) {
    runAfter(fwdDelay, [this, ip, face] {
        std::string name = ip->getContentName();
        DataPacket *hit = cs->lookup(name);
        if (consumerFace[face]) {
            MetricsCollector::getInstance()->recordEdgeCs(hit != nullptr);
            if (hit) MetricsCollector::getInstance()->recordEdgeCsCross(hit->getFetchedFor() != ip->getOriginConsumer());
        }
        else MetricsCollector::getInstance()->recordTransitCs(hit != nullptr);
        // NDNLPv2 PIT token: on a clinician's access link the answer echoes
        // the token (nonce) of the Interest it answers.
        int token = consumerFace[face] ? ip->getNonce() : 0;
        if (hit) {
            csHits++;
            DataPacket *d = hit->dup();
            d->setPitToken(token);
            tx.send(d, face);
            delete ip;
            return;
        }
        csMisses++;
        auto it = pit.find(name);
        if (it != pit.end() && it->second.expires <= simTime()) { pit.erase(it); it = pit.end(); }
        if (it != pit.end()) {
            PitEntry &e = it->second;
            e.faces[face].push_back({token, ip->getOriginConsumer()});
            e.expires = std::max(e.expires, simTime() + ip->getLifetime());
            auto ifs = fib->getInterfaces(name);
            if (simTime() - e.lastForwarded >= suppression && !ifs.empty()) {
                e.lastForwarded = simTime();
                tx.send(ip, ifs[rr++ % ifs.size()]);   // retransmission after suppression interval
            } else {
                delete ip;
            }
            return;
        }
        if ((int)pit.size() >= pitSize) {
            sendNack(face, name, ip->getNonce(), 1);
            delete ip;
            return;
        }
        PitEntry &e = pit[name];
        e.expires = simTime() + ip->getLifetime();
        e.lastForwarded = simTime();
        e.faces[face].push_back({token, ip->getOriginConsumer()});
        auto ifs = fib->getInterfaces(name);
        if (ifs.empty()) {
            pit.erase(name);
            sendNack(face, name, ip->getNonce(), 0);
            delete ip;
            return;
        }
        tx.send(ip, ifs[rr++ % ifs.size()]);
    });
}

void Router::enforce(InterestPacket *ip, int face) {
    Ctx c;
    c.face = face;
    c.name = ip->getContentName();
    c.requester = ip->getRequesterId();
    c.nonce = ip->getNonce();
    c.breakGlass = ip->getBreakGlass();
    c.attack = ip->getAttack();
    c.origin = ip->getOriginConsumer();
    c.arrival = simTime();
    c.lifetime = ip->getLifetime();
    c.iv.name = c.name;
    c.iv.requesterId = c.requester;
    c.iv.nonceHex = ip->getNonceHex();
    c.iv.lifetimeMs = (int)(ip->getLifetime() * 1000);
    c.iv.signingTs = ip->getSigningTimestamp();
    c.iv.signatureB64 = ip->getSignatureValue();
    c.iv.presentationMode = ip->getPresentationMode();
    c.iv.didDocJson = ip->getDidDocJson();
    c.iv.vcJson = ip->getVcJson();
    c.iv.vcId = ip->getVcId();
    c.iv.breakGlass = c.breakGlass;
    delete ip;

    long long now = kSimEpochBase + (long long)simTime().dbl();
    const CostModel &cm = CostModel::instance();

    if (framework == "didvc") {
        if (statusMaxAge > 0 && now - freshAt > (long long)statusMaxAge) {
            // No verified status update for longer than the staleness bound:
            // fail closed rather than trust an outdated replica.
            runAfter(fwdDelay, [this, c] { afterDecision(c, 7, "", 0, 0, false, 7); });
            return;
        }
        Decision d = engine.evaluate(c.iv, now);
        c.rk = d.rk;
        int nack = verdictToNackReason(d.verdict);
        double cpu = cpuFactor * d.modeledCpu;
        runAfter(fwdDelay + cpu, [this, c, d, nack, cpu]() mutable {
            afterDecision(c, (int)d.verdict, d.rule, cpu, d.measuredCpu, false, nack);
        });
        return;
    }

    // abac / scbac: PEP local stage.
    double cost = fwdDelay + cpuFactor * cm.cost(Stage::SESSION_LOOKUP);
    if (c.iv.signatureB64.empty() || c.requester.empty()) {
        runAfter(cost, [this, c, cost] { afterDecision(c, (int)Verdict::DENY_NO_CREDENTIAL, "", cost, 0, false, 2); });
        return;
    }
    if (replaySeen(c.requester, c.iv.nonceHex, c.iv.signingTs, now)) {
        runAfter(cost, [this, c, cost] { afterDecision(c, (int)Verdict::DENY_REPLAY, "", cost, 0, false, 8); });
        return;
    }
    if (dcTtl > 0) {
        auto ii = identityCache.find(c.requester);
        ResourceAttrs ra = ResourceAttrs::fromName(c.name);
        std::string key = c.requester + "|" + ra.unit + "|" + ra.type + "|" + (c.breakGlass ? "1" : "0");
        auto di = decisionCache.find(key);
        if (ii != identityCache.end() && ii->second.expires > simTime() &&
            di != decisionCache.end() && di->second.expires > simTime()) {
            cost += cpuFactor * cm.cost(Stage::INTEREST_SIG_VERIFY);
            std::string in = interestSigningInput(c.name, c.requester, c.iv.nonceHex, c.iv.lifetimeMs,
                                                  c.iv.signingTs, c.iv.vcId, c.breakGlass, "");
            bool ok = CryptoEngine::ed25519Verify(ii->second.pk, Bytes(in.begin(), in.end()),
                                                  CryptoEngine::fromBase64Url(c.iv.signatureB64));
            MetricsCollector::getInstance()->recordDecisionCache(true);
            CachedDecision cd = di->second;
            c.rk = cd.rk;
            runAfter(cost, [this, c, cd, ok, cost] {
                if (!ok) afterDecision(c, (int)Verdict::DENY_SIGNATURE, "", cost, 0, true, 2);
                else if (cd.granted) afterDecision(c, 0, "cached", cost, 0, true, -1);
                else afterDecision(c, (int)Verdict::DENY_POLICY, "", cost, 0, true, cd.denyReason);
            });
            return;
        }
        MetricsCollector::getInstance()->recordDecisionCache(false);
    }
    // Optional speculative fetch: a PEP may request the record upstream while
    // the remote decision is pending, hiding the round trip on content misses.
    if (speculativeFetch && cs->lookup(c.name) == nullptr && pit.find(c.name) == pit.end() &&
        (int)pit.size() < pitSize) {
        PitEntry &e = pit[c.name];
        e.expires = simTime() + c.lifetime;
        e.lastForwarded = simTime();
        e.prefetchFor = c.origin;
        forwardUpstream(c.name, c.lifetime, nullptr);
    }
    runAfter(cost, [this, c] { queryAuthz(c); });
}

bool Router::replaySeen(const std::string &req, const std::string &nonce, long long ts, long long now) {
    while (!nonceAge.empty() && nonceAge.front().first < now - (long long)replayWindow) {
        nonceSet.erase(nonceAge.front().second);
        nonceAge.pop_front();
    }
    if (ts < now - (long long)replayWindow || ts > now + 5) return true;
    std::string k = req + "|" + nonce;
    if (!nonceSet.insert(k).second) return true;
    nonceAge.emplace_back(ts, k);
    return false;
}

void Router::queryAuthz(Ctx c) {
    int64_t id = nextReq++;
    PendingAuthz &p = pending[id];
    p.ctx = c;
    p.sentAt = simTime();
    std::string in = interestSigningInput(c.name, c.requester, c.iv.nonceHex, c.iv.lifetimeMs,
                                          c.iv.signingTs, c.iv.vcId, c.breakGlass, "");
    for (int s : authzServers) {
        auto *r = new AuthzRequest(framework == "abac" ? "AuthzRequest" : "EndorseRequest");
        r->setSrcId(getId());
        r->setDstId(s);
        r->setReqId(id);
        r->setRequesterId(c.requester.c_str());
        r->setContentName(c.name.c_str());
        r->setSignedBytes(in.c_str());
        r->setSignatureValue(c.iv.signatureB64.c_str());
        r->setBreakGlass(c.breakGlass);
        // request header + name + requester + nonce + timestamp + signature
        r->setByteLength(24 + (long)c.name.size() + (long)c.requester.size() + 16 + 8 + 64);
        sendCtrl(r, s);
        authzSent++;
    }
    Job *t = new Job();
    t->fn = [this, id] { authzTimeout(id); };
    p.timeout = t;
    scheduleAt(simTime() + authzTimeoutSec, t);
}

void Router::onAuthzResponse(AuthzResponse *r) {
    auto it = pending.find(r->getReqId());
    if (it == pending.end() || it->second.done) return;
    PendingAuthz &p = it->second;
    const CostModel &cm = CostModel::instance();
    auto kk = gServerKeys.find(r->getSrcId());
    std::string dec = std::string(r->getRequesterId()) + "|" + p.ctx.name + "|" +
                      std::to_string(r->getReqId()) + "|" + (r->getGranted() ? "permit" : "deny");
    if (kk == gServerKeys.end() ||
        !CryptoEngine::ed25519Verify(kk->second, Bytes(dec.begin(), dec.end()),
                                     CryptoEngine::fromBase64Url(r->getDecisionSig())))
        return;
    if (r->getGranted()) {
        p.grants++;
        p.sealedRk = r->getSealedReKey();
        p.signingPk = r->getSigningPublicKey();
    } else {
        p.denies++;
        p.lastDeny = r->getDenyReason();
        if (std::strlen(r->getSigningPublicKey()) > 0) p.signingPk = r->getSigningPublicKey();
    }
    int nsrv = (int)authzServers.size();
    bool grant = p.grants >= quorum;
    bool deny = p.denies > nsrv - quorum;
    if (!grant && !deny) return;
    p.done = true;
    cancelAndDelete(p.timeout);
    p.timeout = nullptr;
    Ctx c = p.ctx;
    double cost = 0;
    if (grant) {
        cost += cpuFactor * cm.cost(Stage::REKEY_UNSEAL);
        EnforcementEngine::unsealReKey(sealKey, p.sealedRk, c.rk);
    }
    auto inv = invalidatedAt.find(c.requester);
    bool stale = inv != invalidatedAt.end() && p.sentAt < inv->second;
    if (dcTtl > 0 && !stale) {
        ResourceAttrs ra = ResourceAttrs::fromName(c.name);
        std::string key = c.requester + "|" + ra.unit + "|" + ra.type + "|" + (c.breakGlass ? "1" : "0");
        decisionCache[key] = {grant, p.lastDeny, c.rk, simTime() + dcTtl};
        if (!p.signingPk.empty())
            identityCache[c.requester] = {CryptoEngine::fromBase64Url(p.signingPk), simTime() + dcTtl};
    }
    int lastDeny = p.lastDeny;
    pending.erase(it);
    runAfter(cost, [this, c, grant, lastDeny, cost] {
        if (grant) afterDecision(c, 0, "remote", cost, 0, false, -1);
        else afterDecision(c, lastDeny == 4 ? (int)Verdict::DENY_REVOKED :
                              lastDeny == 3 ? (int)Verdict::DENY_SUSPENDED : (int)Verdict::DENY_POLICY,
                           "", cost, 0, false, lastDeny);
    });
}

void Router::authzTimeout(int64_t id) {
    auto it = pending.find(id);
    if (it == pending.end()) return;
    it->second.timeout = nullptr;     // this Job is being executed and deleted
    Ctx c = it->second.ctx;
    pending.erase(it);
    afterDecision(c, 7, "", 0, 0, false, 7);
}

void Router::afterDecision(Ctx c, int verdictCode, const std::string &rule, double cpu,
                           double measured, bool dcHit, int nackReason) {
    MetricsCollector::DecisionRecord rec;
    rec.t = simTime().dbl();
    rec.node = getId();
    rec.requester = c.requester;
    rec.name = c.name;
    rec.verdict = verdictCode;
    rec.decisionDelay = (simTime() - c.arrival).dbl();
    rec.modeledCpu = cpu;
    rec.measuredCpu = measured;
    rec.decisionCacheHit = dcHit;
    rec.breakGlass = c.breakGlass;
    rec.attack = c.attack;
    rec.rule = rule;
    bool grant = (verdictCode == 0);
    if (grant) rec.csHit = cs->lookup(c.name) != nullptr;
    MetricsCollector::getInstance()->recordDecision(rec);
    if (!grant) {
        deniedCount++;
        sendNack(c.face, c.name, c.nonce, nackReason < 0 ? 2 : nackReason);
        return;
    }
    granted++;
    if (rule == "BG" && issuerId >= 0) {
        auto *a = new AuditRecord("Audit");
        a->setSrcId(getId());
        a->setDstId(issuerId);
        a->setRequesterId(c.requester.c_str());
        a->setContentName(c.name.c_str());
        a->setGrantedAt(simTime().dbl());
        std::string rec = c.requester + "|" + c.name + "|" + std::to_string(simTime().dbl());
        a->setEdgeSig(CryptoEngine::toBase64Url(CryptoEngine::ed25519Sign(
            auditKey.privateKey, Bytes(rec.begin(), rec.end()))).c_str());
        a->setByteLength(24 + (long)c.requester.size() + (long)c.name.size() + 8 + 64);
        MetricsCollector::getInstance()->auditSent();
        double cost = cpuFactor * CostModel::instance().edSign();
        runAfter(cost, [this, a] { sendCtrl(a, issuerId); });
    }
    serveGranted(c, 0);
}

void Router::serveGranted(const Ctx &c, double) {
    DataPacket *hit = cs->lookup(c.name);
    MetricsCollector::getInstance()->recordEdgeCs(hit != nullptr);
    if (hit) MetricsCollector::getInstance()->recordEdgeCsCross(hit->getFetchedFor() != c.origin);
    if (hit) {
        csHits++;
        double cost = 0;
        DataPacket *out = personalize(hit, c, cost);
        int face = c.face;
        runAfter(cost, [this, out, face] { tx.send(out, face); });
        return;
    }
    csMisses++;
    auto it = pit.find(c.name);
    if (it != pit.end() && it->second.expires <= simTime()) { pit.erase(it); it = pit.end(); }
    if (it != pit.end()) {
        PitEntry &e = it->second;
        e.consumers.push_back(c);
        e.expires = std::max(e.expires, simTime() + c.lifetime);
        if (simTime() - e.lastForwarded >= suppression) {
            e.lastForwarded = simTime();
            forwardUpstream(c.name, c.lifetime, nullptr);
        }
        return;
    }
    if ((int)pit.size() >= pitSize) {
        sendNack(c.face, c.name, c.nonce, 1);
        return;
    }
    PitEntry &e = pit[c.name];
    e.expires = simTime() + c.lifetime;
    e.lastForwarded = simTime();
    e.consumers.push_back(c);
    forwardUpstream(c.name, c.lifetime, nullptr);
}

void Router::forwardUpstream(const std::string &name, double lifetime, InterestPacket *) {
    auto ifs = fib->getInterfaces(name);
    if (ifs.empty()) {
        auto it = pit.find(name);
        if (it != pit.end()) {
            for (auto &c : it->second.consumers) sendNack(c.face, name, c.nonce, 0);
            for (auto &ft : it->second.faces)
                for (auto &tk : ft.second) sendNack(ft.first, name, tk.first, 0);
            pit.erase(it);
        }
        return;
    }
    auto *up = new InterestPacket("Interest");
    up->setContentName(name.c_str());
    up->setNonce(intuniform(1, 0x7fffffff));
    up->setLifetime(lifetime);
    up->setByteLength(kInterestFixed + (long)name.size());
    tx.send(up, ifs[rr++ % ifs.size()]);
}

DataPacket *Router::personalize(const DataPacket *tmpl, const Ctx &c, double &cost) {
    PreCapsule cap{CryptoEngine::fromBase64Url(tmpl->getCapsuleE()),
                   CryptoEngine::fromBase64Url(tmpl->getCapsuleV()),
                   CryptoEngine::fromBase64Url(tmpl->getCapsuleS())};
    PreCFrag f;
    bool ok = UmbralPRE::reencapsulate(c.rk, cap, f);
    cost = cpuFactor * CostModel::instance().cost(Stage::PRE_REENCAPSULATE);
    MetricsCollector::getInstance()->recordReencapsulation(cost);
    DataPacket *d = tmpl->dup();
    if (ok) {
        d->setCfragE1(CryptoEngine::toBase64Url(f.E1).c_str());
        d->setCfragV1(CryptoEngine::toBase64Url(f.V1).c_str());
        d->setCfragX(CryptoEngine::toBase64Url(f.X).c_str());
        d->setByteLength(tmpl->getByteLength() + (long)f.wireSize());
    }
    d->setRecipient(c.origin);
    d->setIsCritical(c.breakGlass);
    d->setPitToken(c.nonce);
    return d;
}

void Router::sendNack(int face, const std::string &name, int nonce, int reason) {
    auto *n = new NACKPacket("NACK");
    n->setContentName(name.c_str());
    n->setNonce(nonce);
    n->setReason(reason);
    n->setByteLength(kNackBytes);
    tx.send(n, face);
}

void Router::onData(DataPacket *d) {
    runAfter(fwdDelay, [this, d] {
        std::string name = d->getContentName();
        auto it = pit.find(name);
        if (it == pit.end()) { delete d; return; }     // unsolicited: neither cached nor forwarded
        if (!d->getNoCache()) {
            DataPacket *stored = d->dup();
            if (!it->second.consumers.empty()) stored->setFetchedFor(it->second.consumers.front().origin);
            else if (it->second.prefetchFor >= 0) stored->setFetchedFor(it->second.prefetchFor);
            else for (auto &ft : it->second.faces)
                if (consumerFace[ft.first] && !ft.second.empty()) { stored->setFetchedFor(ft.second.front().second); break; }
            cs->insert(name, stored);
        }
        for (auto &ft : it->second.faces) {
            if (!consumerFace[ft.first]) { tx.send(d->dup(), ft.first); continue; }
            for (auto &tk : ft.second) {                  // one copy per outstanding Interest
                DataPacket *copy = d->dup();
                copy->setPitToken(tk.first);
                tx.send(copy, ft.first);
            }
        }
        for (const Ctx &c : it->second.consumers) {
            double cost = 0;
            DataPacket *out = personalize(d, c, cost);
            int face = c.face;
            runAfter(cost, [this, out, face] { tx.send(out, face); });
        }
        pit.erase(it);
        delete d;
    });
}

void Router::onNack(NACKPacket *n) {
    runAfter(fwdDelay, [this, n] {
        std::string name = n->getContentName();
        auto it = pit.find(name);
        if (it != pit.end()) {
            for (auto &ft : it->second.faces)
                for (auto &tk : ft.second) {
                    NACKPacket *copy = n->dup();
                    copy->setNonce(tk.first ? tk.first : n->getNonce());
                    tx.send(copy, ft.first);
                    if (!consumerFace[ft.first]) break;
                }
            for (const Ctx &c : it->second.consumers) sendNack(c.face, name, c.nonce, n->getReason());
            pit.erase(it);
        }
        delete n;
    });
}

void Router::purgePit() {
    for (auto it = pit.begin(); it != pit.end();) {
        if (it->second.expires <= simTime()) it = pit.erase(it);
        else ++it;
    }
    for (auto it = decisionCache.begin(); it != decisionCache.end();) {
        if (it->second.expires <= simTime()) it = decisionCache.erase(it);
        else ++it;
    }
}

// ---------------------------------------------------------- status list

void Router::flood(cPacket *p, int except) {
    for (int i = 0; i < tx.size(); i++)
        if (i != except && !consumerFace[i]) tx.send(p->dup(), i);
    delete p;
}

bool Router::applyDeltaJson(const std::string &json, int fromNeighbour) {
    StatusDelta d = StatusDelta::fromJson(json);
    int before = status.version();
    auto res = status.applyDelta(d, issuerPk);
    if (res == StatusList::ApplyResult::BAD_SIGNATURE) return false;
    versionIssuedAt[d.newVersion] = d.issuedAt;
    if (res == StatusList::ApplyResult::GAP) {
        storedDeltas[d.newVersion] = json;
        if (!syncInFlight && fromNeighbour >= 0) {
            syncInFlight = true;
            int target = fromNeighbour;
            runAt(simTime() + par("gapGrace").doubleValue(), [this, target] {
                // Pull only if the gap is still open (the missing delta may
                // simply have taken a slower path).
                bool gap = false;
                for (auto &kv : storedDeltas) if (kv.first > status.version() + 1) gap = true;
                if (!gap) { syncInFlight = false; return; }
                auto *r = new VCListSyncRequest("StatusGapPull");
                r->setSrcId(getId());
                r->setDstId(target);
                r->setKnownVersion(status.version());
                r->setByteLength(32);
                sendCtrl(r, target);
                runAt(simTime() + 1.0, [this] { syncInFlight = false; });
            });
        }
        return true;
    }
    if (res == StatusList::ApplyResult::APPLIED) storedDeltas[d.newVersion] = json;
    // Drain buffered deltas that are now in order.
    bool progress = true;
    while (progress) {
        progress = false;
        auto nx = storedDeltas.find(status.version() + 1);
        if (nx != storedDeltas.end() &&
            status.applyDelta(StatusDelta::fromJson(nx->second), issuerPk) == StatusList::ApplyResult::APPLIED)
            progress = true;
    }
    refreshFromVersion();
    if (isEdge)
        for (int v = before + 1; v <= status.version(); v++)
            MetricsCollector::getInstance()->stateApplied(getId(), v, simTime().dbl());
    return true;
}

void Router::refreshFromVersion() {
    auto it = versionIssuedAt.find(status.version());
    if (it != versionIssuedAt.end()) freshAt = std::max(freshAt, it->second);
}

void Router::refloodDelta(const std::string &json, int version, int except) {
    if (!floodedDeltas.insert(version).second) return;
    auto *p = new VCListDeltaPacket("StatusDelta");
    p->setDeltaJson(json.c_str());
    p->setListVersion(version);
    p->setByteLength(16 + (long)json.size());
    flood(p, except);
}

void Router::onDelta(VCListDeltaPacket *p, int face) {
    if (framework.rfind("didvc", 0) != 0) { delete p; return; }
    double cost = fwdDelay + cpuFactor * CostModel::instance().edVerify();
    int from = face >= 0 ? faceNeighbourId[face] : -1;
    runAfter(cost, [this, p, face, from] {
        // A delta whose issuer signature fails is dropped, never flooded, so a
        // forged version cannot pre-empt the flood of the genuine one.
        if (!applyDeltaJson(p->getDeltaJson(), from)) { delete p; return; }
        // Flood each version exactly once; keyed by version so a delta that
        // arrives out of order is still forwarded.
        if (floodedDeltas.insert(p->getListVersion()).second) flood(p, face);
        else delete p;
    });
}

void Router::onSnapshot(VCListSnapshotPacket *p, int face) {
    if (framework.rfind("didvc", 0) != 0) { delete p; return; }
    double cost = fwdDelay + cpuFactor * CostModel::instance().edVerify();
    runAfter(cost, [this, p, face] {
        int before = status.version();
        StatusSnapshot s = StatusSnapshot::fromJson(p->getSnapshotJson());
        if (!s.verify(issuerPk)) { delete p; return; }
        bool applied = status.applySnapshot(s, issuerPk) == StatusList::ApplyResult::APPLIED;
        if (status.version() >= s.version) freshAt = std::max(freshAt, s.issuedAt);
        if (applied || s.version == status.version()) {
            storedSnapshot = p->getSnapshotJson();
            for (auto it = storedDeltas.begin(); it != storedDeltas.end();)
                if (it->first <= s.version) it = storedDeltas.erase(it); else ++it;
        }
        if (isEdge)
            for (int v = before + 1; v <= status.version(); v++)
                MetricsCollector::getInstance()->stateApplied(getId(), v, simTime().dbl());
        if (floodedSnapshots.insert(p->getIssuedAtSim()).second) { flood(p, face); return; }
        delete p;
    });
}

void Router::onSyncRequest(VCListSyncRequest *r) {
    int known = r->getKnownVersion();
    if (known > status.version()) {
        // The neighbour is ahead of us: pull from it (unless a pull is open).
        if (!syncInFlight && std::string(r->getName()) == "StatusBeacon") {
            syncInFlight = true;
            auto *q = new VCListSyncRequest("StatusGapPull");
            q->setSrcId(getId());
            q->setDstId(r->getSrcId());
            q->setKnownVersion(status.version());
            q->setByteLength(32);
            sendCtrl(q, r->getSrcId());
            runAt(simTime() + 1.0, [this] { syncInFlight = false; });
        }
        return;
    }
    if (known == status.version() && std::string(r->getName()) == "StatusBeacon") return;
    auto *resp = new StatusSyncResponse("StatusSync");
    resp->setSrcId(getId());
    resp->setDstId(r->getSrcId());
    long bytes = 24;
    // Deltas suffice when we still hold every version after `known`;
    // otherwise send the stored snapshot plus the deltas after it.
    bool deltasCover = true;
    for (int v = known + 1; v <= status.version(); v++)
        if (!storedDeltas.count(v)) { deltasCover = false; break; }
    if (!deltasCover && !storedSnapshot.empty()) {
        resp->setSnapshotJson(storedSnapshot.c_str());
        bytes += (long)storedSnapshot.size();
    }
    std::string arr = "[";
    bool first = true;
    for (auto &kv : storedDeltas) {
        if (kv.first <= known || kv.first > status.version()) continue;
        arr += (first ? "" : ",") + kv.second;
        bytes += (long)kv.second.size();
        first = false;
    }
    arr += "]";
    resp->setDeltasJson(arr.c_str());
    resp->setListVersion(status.version());
    resp->setByteLength(bytes);
    sendCtrl(resp, r->getSrcId());
}

void Router::onSyncResponse(StatusSyncResponse *r) {
    int before = status.version();
    std::string snap = r->getSnapshotJson();
    if (!snap.empty()) {
        StatusSnapshot s = StatusSnapshot::fromJson(snap);
        auto res = status.applySnapshot(s, issuerPk);
        if (res != StatusList::ApplyResult::BAD_SIGNATURE && status.version() >= s.version)
            freshAt = std::max(freshAt, s.issuedAt);
        if (res == StatusList::ApplyResult::APPLIED) storedSnapshot = snap;
    }
    auto fit = routes.find(r->getSrcId());
    int fromFace = fit != routes.end() ? fit->second : -1;
    for (const std::string &dj : Json::splitArrayElements(r->getDeltasJson())) {
        StatusDelta d = StatusDelta::fromJson(dj);
        auto res = status.applyDelta(d, issuerPk);
        if (res == StatusList::ApplyResult::BAD_SIGNATURE) continue;
        versionIssuedAt[d.newVersion] = d.issuedAt;
        if (res == StatusList::ApplyResult::APPLIED || res == StatusList::ApplyResult::GAP)
            storedDeltas[d.newVersion] = dj;
    }
    bool progress = true;
    while (progress) {
        progress = false;
        auto nx = storedDeltas.find(status.version() + 1);
        if (nx != storedDeltas.end() &&
            status.applyDelta(StatusDelta::fromJson(nx->second), issuerPk) == StatusList::ApplyResult::APPLIED)
            progress = true;
    }
    refreshFromVersion();
    // Versions recovered by a pull are flooded on like any other, so a loss
    // is repaired once, at the hop where it happened, not hop by hop.
    for (int v = before + 1; v <= status.version(); v++) {
        auto sd = storedDeltas.find(v);
        if (sd != storedDeltas.end()) refloodDelta(sd->second, v, fromFace);
    }
    if (isEdge)
        for (int v = before + 1; v <= status.version(); v++)
            MetricsCollector::getInstance()->stateApplied(getId(), v, simTime().dbl());
    syncInFlight = false;
}

void Router::sendCtrl(CtrlPacket *p, int dst) {
    auto it = routes.find(dst);
    if (it != routes.end()) tx.send(p, it->second);
    else if (defaultCtrlFace >= 0) tx.send(p, defaultCtrlFace);
    else delete p;
}

void Router::finish() {
    recordScalar("csHits", csHits);
    recordScalar("csMisses", csMisses);
    recordScalar("granted", granted);
    recordScalar("denied", deniedCount);
    recordScalar("authzSent", authzSent);
    recordScalar("cpuBusy", cpuBusy);
    recordScalar("statusVersion", status.version());
    recordScalar("sessions", (double)engine.sessions());
    recordScalar("csEvictions", (double)cs->evictions());
    for (auto &kv : pending) if (kv.second.timeout) cancelAndDelete(kv.second.timeout);
    pending.clear();
    cancelAndDelete(purgeTimer);
    purgeTimer = nullptr;
    cancelAndDelete(pullTimer);
    pullTimer = nullptr;
    cancelAndDelete(beaconTimer);
    beaconTimer = nullptr;
    tx.clear();
    delete cs; cs = nullptr;
    delete fib; fib = nullptr;
    gServerKeys.clear();
}

} // namespace ndnpreencryption
