#include "Issuer.h"

#include <cstring>
#include <sstream>

#include "../security/DID.h"
#include "../security/EnforcementEngine.h"

namespace ndnpreencryption {

extern std::map<int, Bytes> gAuditKeys;   // defined in Router.cc

Define_Module(Issuer);

void Issuer::initialize(int stage) {
    if (stage == 0) {
        framework = par("framework").stdstringValue();
        snapshotInterval = par("snapshotInterval").doubleValue();
        vcValidity = par("vcValidity").doubleValue();
        reactivationDelay = par("reactivationDelay").doubleValue();
        revocationRate = par("revocationRate").doubleValue();
        suspensionRate = par("suspensionRate").doubleValue();
        pushStatus = par("statusDissemination").stdstringValue() != "pull";
        statusListName = par("statusListName").stdstringValue();
        pushInvalidation = par("pushInvalidation").boolValue();
        failAt = par("failAt").doubleValue();
        recoverAt = par("recoverAt").doubleValue();
        std::istringstream ss(par("revocationTimes").stdstringValue());
        std::string tok;
        while (std::getline(ss, tok, ','))
            if (!tok.empty()) scheduledRevocations.push_back(std::stod(tok));

        signingKey = CryptoEngine::generateEd25519KeyPair();
        issuerDid = DID::fromEd25519PublicKey(signingKey.publicKey);
        ownerPre = UmbralPRE::keygen();
        sealKey = CryptoEngine::randomBytes(32);
        tx.init(this, "port", false);
    }
    else {
        routes = buildControlRoutes(this);
        for (cModule *c : findModulesByType(this, "Consumer")) {
            std::string at = c->par("attackType").stdstringValue();
            if (at != "none" && at != "tampered_vc") continue;   // adversaries are not staff
            if (at == "tampered_vc") insiderAttackers.insert(c->getId());   // never drawn for revocation
            roster[c->getId()] = {c->par("userRole").stdstringValue(), c->par("unit").stdstringValue(),
                                  (int)c->par("clearance").intValue()};
        }
        for (cModule *r : findModulesByType(this, "Router")) {
            bool edge = r->par("consumerFaceStart").intValue() >= 0;
            for (int i = 0; !edge && i < r->gateSize("port"); i++) edge = isConsumerModule(peerOfGate(r, i));
            if (edge) edgeRouters.push_back(r->getId());
        }
        const char *target = framework == "abac" ? "AuthzServer" : framework == "scbac" ? "AuthzServer" : nullptr;
        if (target)
            for (cModule *m : findModulesByType(this, target)) {
                std::string mode = m->par("mode").stdstringValue();
                if ((framework == "abac" && mode == "pdp") || (framework == "scbac" && mode == "validator"))
                    authzTargets.push_back(m->getId());
            }
        snapshotTimer = new cMessage("snapshot");
        revokeTimer = new cMessage("revoke");
        suspendTimer = new cMessage("suspend");
        scheduledTimer = new cMessage("scheduledRevoke");
        reactivateTimer = new cMessage("reactivate");
        if (framework.rfind("didvc", 0) == 0 && pushStatus)
            scheduleAt(snapshotInterval, snapshotTimer);
        double start = par("lifecycleStart").doubleValue();
        if (revocationRate > 0) scheduleAt(start + exponential(1.0 / revocationRate), revokeTimer);
        if (suspensionRate > 0) scheduleAt(start + exponential(1.0 / suspensionRate), suspendTimer);
        if (!scheduledRevocations.empty()) scheduleAt(scheduledRevocations.front(), scheduledTimer);
        if (failAt >= 0 && recoverAt > failAt) {
            recoverTimer = new cMessage("recover");
            scheduleAt(recoverAt, recoverTimer);
        }
    }
}

bool Issuer::down() const {
    double t = simTime().dbl();
    return failAt >= 0 && t >= failAt && (recoverAt < 0 || t < recoverAt);
}

bool Issuer::holderEnrolledAndActive(const std::string &did) const {
    auto it = holders.find(did);
    return it != holders.end() && it->second.enrolled && it->second.status == CredStatus::ACTIVE;
}

void Issuer::handleMessage(cMessage *msg) {
    if (tx.handleTimer(msg)) return;
    bool redelivered = takeRedelivery(msg);
    if (msg == snapshotTimer) {
        if (!down()) publishSnapshot();
        scheduleAt(simTime() + snapshotInterval, snapshotTimer);
        return;
    }
    if (msg == revokeTimer || msg == suspendTimer || msg == scheduledTimer) {
        bool revoke = (msg != suspendTimer);
        // An offline credential authority publishes no status changes.
        std::string did = down() ? std::string() : pickActiveHolder();
        if (!did.empty()) {
            if (revoke) { changeStatus(did, CredStatus::REVOKED, "revoked"); revocations++; }
            else {
                changeStatus(did, CredStatus::SUSPENDED, "suspended");
                suspensions++;
                reactivationsDue.push_back({did, simTime() + reactivationDelay});
                if (!reactivateTimer->isScheduled()) scheduleAt(simTime() + reactivationDelay, reactivateTimer);
            }
        }
        if (msg == revokeTimer) scheduleAt(simTime() + exponential(1.0 / revocationRate), revokeTimer);
        else if (msg == suspendTimer) scheduleAt(simTime() + exponential(1.0 / suspensionRate), suspendTimer);
        else {
            scheduledRevocations.erase(scheduledRevocations.begin());
            if (!scheduledRevocations.empty()) scheduleAt(scheduledRevocations.front(), scheduledTimer);
        }
        return;
    }
    if (msg == recoverTimer) {
        // Back online: publish the current list at once so that edges become
        // fresh again without waiting for the next periodic snapshot.
        if (framework.rfind("didvc", 0) == 0 && pushStatus) publishSnapshot();
        return;
    }
    if (msg == reactivateTimer) {
        if (down()) {                         // an offline authority changes nothing
            if (recoverAt > simTime().dbl()) scheduleAt(recoverAt, reactivateTimer);
            return;
        }
        simtime_t next = SIMTIME_MAX;
        std::vector<Pending> keep;
        for (auto &p : reactivationsDue) {
            if (p.when <= simTime()) {
                auto it = holders.find(p.did);
                if (it != holders.end() && it->second.status == CredStatus::SUSPENDED) {
                    changeStatus(p.did, CredStatus::ACTIVE, "reactivated");
                    reactivations++;
                }
            } else {
                keep.push_back(p);
                if (p.when < next) next = p.when;
            }
        }
        reactivationsDue = keep;
        if (next < SIMTIME_MAX) scheduleAt(next, reactivateTimer);
        return;
    }
    if (!redelivered && handleLinkLoss(this, msg)) return;
    if (auto a = dynamic_cast<AuditRecord *>(msg)) {
        // Accept an audit record only under the signing key of the edge that sent it.
        auto k = gAuditKeys.find(a->getSrcId());
        std::string rec = std::string(a->getRequesterId()) + "|" + a->getContentName() + "|" +
                          std::to_string(a->getGrantedAt());
        bool ok = k != gAuditKeys.end() &&
                  CryptoEngine::ed25519Verify(k->second, Bytes(rec.begin(), rec.end()),
                                              CryptoEngine::fromBase64Url(a->getEdgeSig()));
        if (ok) MetricsCollector::getInstance()->auditReceived(simTime().dbl() - a->getGrantedAt());
        else MetricsCollector::getInstance()->auditRejected();
        delete msg;
        return;
    }
    if (down()) { delete msg; return; }
    if (auto req = dynamic_cast<VCIssueRequest *>(msg)) {
        onIssueRequest(req);
        delete msg;
        return;
    }
    if (auto sr = dynamic_cast<VCListSyncRequest *>(msg)) {
        if (framework.rfind("didvc", 0) == 0 && sr->getKnownVersion() < list.version()) {
            StatusSnapshot s = list.buildSnapshot(issuerDid, statusListName,
                                                  kSimEpochBase + (long long)simTime().dbl());
            s.sign(signingKey.privateKey);
            auto *resp = new StatusSyncResponse("StatusSync");
            resp->setSrcId(getId());
            resp->setDstId(sr->getSrcId());
            resp->setSnapshotJson(s.toJson().c_str());
            resp->setDeltasJson("[]");
            resp->setListVersion(s.version);
            resp->setByteLength(24 + (long)s.toJson().size());
            sendCtrl(resp, sr->getSrcId());
        }
        delete msg;
        return;
    }
    // Anything else addressed to the issuer (flooded status packets coming
    // back, stray control) is dropped.
    delete msg;
}

void Issuer::onIssueRequest(VCIssueRequest *req) {
    std::string did = req->getRequesterId();
    Bytes spk = CryptoEngine::fromBase64Url(req->getSigningPublicKey());
    Bytes ppk = CryptoEngine::fromBase64Url(req->getPrePublicKey());
    std::string canon = did + "|" + req->getRequestedRole() + "|" + req->getRequestedUnit() + "|" +
                        req->getOrganization() + "|" + std::to_string(req->getClearance()) + "|" +
                        std::to_string(req->getNonce()) + "|" + req->getPrePublicKey();
    bool sigOk = spk.size() == 32 && DID::verifyThumbprint(did, spk) &&
                 CryptoEngine::ed25519Verify(spk, Bytes(canon.begin(), canon.end()),
                                             CryptoEngine::fromBase64Url(req->getSignatureValue()));
    auto *resp = new VCIssueResponse("VCIssueResponse");
    resp->setSrcId(getId());
    resp->setDstId(req->getSrcId());
    resp->setRequesterId(did.c_str());

    auto ro = roster.find(req->getSrcId());
    Holder &h = holders[did];
    if (!sigOk || ro == roster.end() || (h.enrolled && h.status != CredStatus::ACTIVE)) {
        resp->setSuccess(false);
        resp->setReason(!sigOk ? "bad request signature" : ro == roster.end() ? "not on staff roster"
                                                                             : credStatusName(h.status));
        resp->setByteLength(64);
        refused++;
        sendCtrl(resp, req->getSrcId());
        return;
    }
    if (!h.enrolled) {
        h.consumerModule = req->getSrcId();
        h.role = ro->second.role;
        h.unit = ro->second.unit;
        h.clearance = ro->second.clearance;
        h.signingPk = spk;
        h.prePk = ppk;
        h.sealedRk = EnforcementEngine::sealReKey(sealKey, UmbralPRE::rekeygen(ownerPre.sk, ppk));
        h.enrolled = true;
        if (framework == "abac" || framework == "scbac") sendIdentityUpdates(did, h);
    }

    if (framework.rfind("didvc", 0) == 0) {
        VerifiableCredential vc;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "#vc-%04ld", issued + 1);
        vc.id = issuerDid + buf;
        vc.issuer = issuerDid;
        vc.validFrom = kSimEpochBase + (long long)simTime().dbl();
        vc.validUntil = vc.validFrom + (long long)vcValidity;
        vc.subject.id = did;
        vc.subject.role = h.role;
        vc.subject.unit = h.unit;
        vc.subject.department = h.unit;
        vc.subject.clearance = h.clearance;
        vc.subject.organization = req->getOrganization();
        vc.subject.specialty = h.role;
        std::snprintf(buf, sizeof(buf), "LIC-%07ld", issued + 1);
        vc.subject.licenseNumber = buf;
        vc.subject.reEncryptionKey = h.sealedRk;
        int idx = nextIndex++;
        h.indices.push_back(idx);
        list.set(idx, CredStatus::ACTIVE);
        vc.statusRef.statusListCredential = statusListName;
        vc.statusRef.statusListIndex = idx;
        vc.statusRef.id = statusListName + "#" + std::to_string(idx);
        vc.proof.created = vc.validFrom;
        vc.proof.verificationMethod = issuerDid + "#keys-1";
        vc.sign(signingKey.privateKey);
        std::string j = vc.toJson();
        resp->setVcJson(j.c_str());
        resp->setByteLength(32 + (long)j.size());
    } else {
        resp->setByteLength(64 + 64);
    }
    resp->setSuccess(true);
    issued++;
    sendCtrl(resp, req->getSrcId());
}

void Issuer::sendIdentityUpdates(const std::string &did, const Holder &h) {
    seq++;
    MetricsCollector::getInstance()->statePublished(seq, simTime().dbl(), "identity");
    for (int dst : authzTargets) {
        auto *u = new IdentityUpdate(framework == "scbac" ? "IdentityTx" : "IdentityUpdate");
        u->setSrcId(getId());
        u->setDstId(dst);
        u->setUserId(did.c_str());
        u->setSigningPublicKey(CryptoEngine::toBase64Url(h.signingPk).c_str());
        u->setRole(h.role.c_str());
        u->setUnit(h.unit.c_str());
        u->setClearance(h.clearance);
        u->setSealedReKey(h.sealedRk.c_str());
        u->setStatus((int)h.status);
        u->setSeq(seq);
        u->setSubmittedAt(simTime().dbl());
        // user id + key + attributes + sealed rk + status/seq + issuer signature
        u->setByteLength(24 + (long)did.size() + 32 + (long)h.role.size() + (long)h.unit.size() + 4 +
                         93 + 12 + 64);
        sendCtrl(u, dst);
    }
}

void Issuer::changeStatus(const std::string &did, CredStatus st, const char *reason) {
    Holder &h = holders[did];
    h.status = st;
    int idx = h.indices.empty() ? -1 : h.indices.back();
    MetricsCollector::getInstance()->lifecycle(did, idx, (int)st, simTime().dbl());
    EV_INFO << "Issuer: " << reason << " " << did << endl;
    if (framework.rfind("didvc", 0) == 0) {
        for (int i : h.indices) {
            list.set(i, st);
            list.bumpVersion();
            MetricsCollector::getInstance()->statePublished(list.version(), simTime().dbl(), reason);
            if (pushStatus) publishDelta(i, st);
        }
    } else if (framework == "abac" || framework == "scbac") {
        sendIdentityUpdates(did, h);
        // BC-AC: a status change is visible only after the block commits, so
        // the validators raise the invalidation as a block event instead.
        if (pushInvalidation && framework == "abac")
            for (int e : edgeRouters) {
                auto *u = new IdentityUpdate("Invalidate");
                u->setSrcId(getId());
                u->setDstId(e);
                u->setUserId(did.c_str());
                u->setStatus((int)st);
                u->setSeq(seq);
                u->setSubmittedAt(simTime().dbl());
                u->setByteLength(24 + (long)did.size() + 12 + 64);
                sendCtrl(u, e);
            }
    }
}

void Issuer::publishDelta(int index, CredStatus st) {
    StatusDelta d;
    d.issuerDid = issuerDid;
    d.newVersion = list.version();
    d.baseVersion = d.newVersion - 1;
    d.index = index;
    d.status = st;
    d.issuedAt = kSimEpochBase + (long long)simTime().dbl();
    d.sign(signingKey.privateKey);
    std::string j = d.toJson();
    auto *p = new VCListDeltaPacket("StatusDelta");
    p->setDeltaJson(j.c_str());
    p->setListVersion(d.newVersion);
    p->setIssuedAtSim(simTime().dbl());
    p->setByteLength(16 + (long)j.size());
    floodOut(p);
    deltas++;
}

void Issuer::publishSnapshot() {
    StatusSnapshot s = list.buildSnapshot(issuerDid, statusListName,
                                          kSimEpochBase + (long long)simTime().dbl());
    s.sign(signingKey.privateKey);
    lastSnapshotJson = s.toJson();
    auto *p = new VCListSnapshotPacket("StatusSnapshot");
    p->setSnapshotJson(lastSnapshotJson.c_str());
    p->setListVersion(s.version);
    p->setIssuedAtSim(simTime().dbl());
    p->setByteLength(16 + (long)lastSnapshotJson.size());
    floodOut(p);
    snapshots++;
}

void Issuer::floodOut(cPacket *pkt) {
    for (int i = 0; i < tx.size(); i++) tx.send(pkt->dup(), i);
    delete pkt;
}

void Issuer::sendCtrl(CtrlPacket *pkt, int dst) {
    auto it = routes.find(dst);
    // Single-homed node behind a UDP face: everything leaves on face 0.
    tx.send(pkt, it != routes.end() ? it->second : 0);
}

std::string Issuer::pickActiveHolder() {
    // Order candidates by consumer module id, not by DID string: DIDs derive
    // from freshly generated keys, and a string order would make the choice
    // differ between otherwise identical runs.
    std::map<int, std::string> active;
    for (auto &kv : holders)
        if (kv.second.enrolled && kv.second.status == CredStatus::ACTIVE &&
            !insiderAttackers.count(kv.second.consumerModule))
            active[kv.second.consumerModule] = kv.first;
    if (active.empty()) return "";
    auto it = active.begin();
    std::advance(it, intuniform(0, (int)active.size() - 1));
    return it->second;
}

void Issuer::finish() {
    recordScalar("vcsIssued", issued);
    recordScalar("issuanceRefused", refused);
    recordScalar("deltasPublished", deltas);
    recordScalar("snapshotsPublished", snapshots);
    recordScalar("revocations", revocations);
    recordScalar("suspensions", suspensions);
    recordScalar("reactivations", reactivations);
    cancelAndDelete(snapshotTimer);
    cancelAndDelete(revokeTimer);
    cancelAndDelete(suspendTimer);
    cancelAndDelete(scheduledTimer);
    cancelAndDelete(reactivateTimer);
    cancelAndDelete(recoverTimer);
    recoverTimer = nullptr;
    snapshotTimer = revokeTimer = suspendTimer = scheduledTimer = reactivateTimer = nullptr;
    tx.clear();
}

} // namespace ndnpreencryption
