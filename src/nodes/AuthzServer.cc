#include "AuthzServer.h"

#include "../security/EnforcementEngine.h"

namespace ndnpreencryption {

Define_Module(AuthzServer);

void AuthzServer::initialize(int stage) {
    if (stage == 0) {
        mode = par("mode").stdstringValue();
        blockInterval = par("blockInterval").doubleValue();
        cpuFactor = par("cpuFactor").doubleValue();
        failAt = par("failAt").doubleValue();
        recoverAt = par("recoverAt").doubleValue();
        key = CryptoEngine::generateEd25519KeyPair();
        tx.init(this, "port", false);
    } else {
        routes = buildControlRoutes(this);
        if (mode == "validator") {
            std::vector<cModule *> issuers = findModulesByType(this, "Issuer");
            bool push = !issuers.empty() && issuers[0]->par("pushInvalidation").boolValue();
            int lowest = getId();
            for (cModule *m : findModulesByType(this, "AuthzServer"))
                if (m->par("mode").stdstringValue() == "validator") lowest = std::min(lowest, m->getId());
            eventPeer = push && lowest == getId();
            if (eventPeer)
                for (cModule *r : findModulesByType(this, "Router")) {
                    bool edge = r->par("consumerFaceStart").intValue() >= 0;
                    for (int i = 0; !edge && i < r->gateSize("port"); i++) edge = isConsumerModule(peerOfGate(r, i));
                    if (edge) edgeRouters.push_back(r->getId());
                }
            blockTimer = new cMessage("block");
            // Blocks are cut on a common schedule (one ordering service).
            scheduleAt(blockInterval, blockTimer);
        }
    }
}

bool AuthzServer::down() const {
    double t = simTime().dbl();
    return failAt >= 0 && t >= failAt && (recoverAt < 0 || t < recoverAt);
}

void AuthzServer::handleMessage(cMessage *msg) {
    if (tx.handleTimer(msg)) return;
    bool redelivered = takeRedelivery(msg);
    if (msg == blockTimer) {
        for (IdentityUpdate *u : mempool) {
            applyUpdate(u);
            if (eventPeer) emitBlockEvent(u);
            delete u;
        }
        mempool.clear();
        scheduleAt(simTime() + blockInterval, blockTimer);
        return;
    }
    if (msg->isSelfMessage() && !redelivered) {   // CPU completion of a request
        auto *resp = check_and_cast<AuthzResponse *>(msg);
        sendCtrl(resp, resp->getDstId());
        return;
    }
    if (!redelivered && handleLinkLoss(this, msg)) return;
    if (auto u = dynamic_cast<IdentityUpdate *>(msg)) {
        if (mode == "pdp") { applyUpdate(u); delete u; }
        else mempool.push_back(u);
        return;
    }
    if (auto r = dynamic_cast<AuthzRequest *>(msg)) {
        if (down()) { droppedWhileDown++; delete r; return; }
        serve(r);
        delete r;
        return;
    }
    delete msg;
}

void AuthzServer::applyUpdate(IdentityUpdate *u) {
    Identity &id = ledger[u->getUserId()];
    id.signingPk = CryptoEngine::fromBase64Url(u->getSigningPublicKey());
    id.role = u->getRole();
    id.unit = u->getUnit();
    id.clearance = u->getClearance();
    id.sealedRk = u->getSealedReKey();
    id.status = u->getStatus();
    MetricsCollector::getInstance()->stateApplied(getId(), u->getSeq(), simTime().dbl());
}

void AuthzServer::serve(AuthzRequest *req) {
    const CostModel &cm = CostModel::instance();
    double cost = cpuFactor * (cm.cost(Stage::INTEREST_SIG_VERIFY) + cm.cost(Stage::POLICY_ONLY) +
                               cm.cost(Stage::DECISION_SIGN));
    auto *resp = new AuthzResponse(mode == "pdp" ? "AuthzResponse" : "EndorseResponse");
    resp->setSrcId(getId());
    resp->setDstId(req->getSrcId());
    resp->setReqId(req->getReqId());
    resp->setRequesterId(req->getRequesterId());
    resp->setResponderKeyId(std::to_string(getId()).c_str());

    int deny = -1;
    auto it = ledger.find(req->getRequesterId());
    if (it == ledger.end()) deny = 2;
    else {
        const Identity &id = it->second;
        std::string in = req->getSignedBytes();
        if (!CryptoEngine::ed25519Verify(id.signingPk, Bytes(in.begin(), in.end()),
                                         CryptoEngine::fromBase64Url(req->getSignatureValue())))
            deny = 2;
        else if (id.status == 1) deny = 4;
        else if (id.status == 2) deny = 3;
        else {
            SubjectAttrs s{id.role, id.unit, id.clearance};
            if (AccessPolicy::evaluate(s, ResourceAttrs::fromName(req->getContentName()),
                                       req->getBreakGlass()).empty())
                deny = 2;
        }
        resp->setSigningPublicKey(CryptoEngine::toBase64Url(id.signingPk).c_str());
        if (deny < 0) resp->setSealedReKey(id.sealedRk.c_str());
    }
    resp->setGranted(deny < 0);
    resp->setDenyReason(deny);
    std::string dec = std::string(req->getRequesterId()) + "|" + req->getContentName() + "|" +
                      std::to_string(req->getReqId()) + "|" + (deny < 0 ? "permit" : "deny");
    resp->setDecisionSig(CryptoEngine::toBase64Url(
        CryptoEngine::ed25519Sign(key.privateKey, Bytes(dec.begin(), dec.end()))).c_str());
    // decision header + requester id + key + sealed rk (when granted) + signature
    resp->setByteLength(24 + (long)std::strlen(req->getRequesterId()) + 32 + (deny < 0 ? 93 : 0) + 64);

    simtime_t start = std::max(simTime(), cpuFree);
    cpuFree = start + cost;
    busy += cost;
    served++;
    scheduleAt(cpuFree, resp);
}

void AuthzServer::emitBlockEvent(IdentityUpdate *u) {
    for (int e : edgeRouters) {
        auto *inv = new IdentityUpdate("Invalidate");
        inv->setSrcId(getId());
        inv->setDstId(e);
        inv->setUserId(u->getUserId());
        inv->setStatus(u->getStatus());
        inv->setSeq(u->getSeq());
        inv->setSubmittedAt(simTime().dbl());
        inv->setByteLength(24 + (long)std::strlen(u->getUserId()) + 12 + 64);
        sendCtrl(inv, e);
    }
}

void AuthzServer::sendCtrl(CtrlPacket *pkt, int dst) {
    auto it = routes.find(dst);
    // Single-homed node behind a UDP face: everything leaves on face 0.
    tx.send(pkt, it != routes.end() ? it->second : 0);
}

void AuthzServer::finish() {
    recordScalar("served", served);
    recordScalar("droppedWhileDown", droppedWhileDown);
    recordScalar("busySeconds", busy);
    MetricsCollector::getInstance()->recordServiceBusy(getId(), busy, served);
    for (auto *u : mempool) delete u;
    mempool.clear();
    cancelAndDelete(blockTimer);
    blockTimer = nullptr;
    tx.clear();
}

} // namespace ndnpreencryption
