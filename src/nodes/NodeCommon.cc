#include "NodeCommon.h"

#include <cstring>
#include <queue>
#include <set>

namespace ndnpreencryption {

void classifyBytes(cPacket *pkt, std::vector<std::pair<ByteClass, long>> &out) {
    out.clear();
    long len = pkt->getByteLength();
    if (auto ip = dynamic_cast<InterestPacket *>(pkt)) {
        long cred = (long)std::strlen(ip->getDidDocJson()) + (long)std::strlen(ip->getVcJson());
        if (ip->getPresentationMode() != 0) cred += (long)std::strlen(ip->getVcId()) + 4;
        long auth = std::strlen(ip->getSignatureValue()) > 0
                    ? (long)std::strlen(ip->getRequesterId()) + kInterestSigFixed : 0;
        if (cred > len) cred = len;
        if (auth > len - cred) auth = len - cred;
        out.emplace_back(ByteClass::INTEREST_BASE, len - cred - auth);
        if (auth > 0) out.emplace_back(ByteClass::INTEREST_AUTH, auth);
        if (cred > 0) out.emplace_back(ByteClass::INTEREST_CREDENTIAL, cred);
    }
    else if (auto dp = dynamic_cast<DataPacket *>(pkt)) {
        long prot = 0;
        if (dp->getEncrypted()) {
            prot = 12 + 16 + 98 + 64;                       // IV, GCM tag, capsule, producer signature
            if (std::strlen(dp->getCfragE1()) > 0) prot += 99;   // re-encapsulation fragment
            if (dp->getKeyOnly()) prot = len;               // key-split: the whole packet is key material
        }
        if (prot > len) prot = len;
        if (len - prot > 0) out.emplace_back(ByteClass::DATA, len - prot);
        if (prot > 0) out.emplace_back(ByteClass::DATA_PROTECTION, prot);
    }
    else if (dynamic_cast<NACKPacket *>(pkt)) out.emplace_back(ByteClass::NACK, len);
    else if (dynamic_cast<AuthzRequest *>(pkt) || dynamic_cast<AuthzResponse *>(pkt)) {
        bool endorse = std::string(pkt->getName()).find("Endorse") != std::string::npos;
        out.emplace_back(endorse ? ByteClass::ENDORSE : ByteClass::AUTHZ, len);
    }
    else if (dynamic_cast<VCIssueRequest *>(pkt) || dynamic_cast<VCIssueResponse *>(pkt))
        out.emplace_back(ByteClass::VC_ISSUE, len);
    else if (dynamic_cast<IdentityUpdate *>(pkt)) out.emplace_back(ByteClass::IDENTITY_UPDATE, len);
    else if (dynamic_cast<VCListDeltaPacket *>(pkt)) out.emplace_back(ByteClass::STATUS_DELTA, len);
    else if (dynamic_cast<VCListSnapshotPacket *>(pkt)) out.emplace_back(ByteClass::STATUS_SNAPSHOT, len);
    else if (dynamic_cast<VCListSyncRequest *>(pkt) || dynamic_cast<StatusSyncResponse *>(pkt))
        out.emplace_back(ByteClass::STATUS_SYNC, len);
    else if (dynamic_cast<AuditRecord *>(pkt)) out.emplace_back(ByteClass::AUDIT, len);
}

void GateTx::init(cSimpleModule *o, const char *base, bool prio) {
    owner = o;
    gateBase = base;
    priority = prio;
    int n = owner->gateSize(base);
    for (int i = 0; i < n; i++) {
        Q *q = new Q();
        q->timer = new cMessage("txTimer");
        q->timer->setContextPointer(this);
        q->timer->setKind(i);
        queues.push_back(q);
    }
}

void GateTx::send(cPacket *pkt, int g) {
    if (g < 0 || g >= (int)queues.size()) { delete pkt; return; }
    Q *q = queues[g];
    if (limit > 0 && q->hi.getLength() + q->lo.getLength() >= limit) {
        drops++;
        delete pkt;
        return;
    }
    bool hi = false;
    if (priority) {
        if (auto ip = dynamic_cast<InterestPacket *>(pkt)) hi = ip->getBreakGlass();
        else if (auto dp = dynamic_cast<DataPacket *>(pkt)) hi = dp->isCritical();
    }
    (hi ? q->hi : q->lo).insert(pkt);
    if (!q->timer->isScheduled()) trySend(g);
}

bool GateTx::handleTimer(cMessage *msg) {
    if (msg->getContextPointer() != this) return false;
    trySend(msg->getKind());
    return true;
}

void GateTx::trySend(int g) {
    Q *q = queues[g];
    if (q->hi.isEmpty() && q->lo.isEmpty()) return;
    cGate *out = owner->gate((gateBase + "$o").c_str(), g);
    cChannel *ch = out->getTransmissionChannel();
    simtime_t fin = ch->getTransmissionFinishTime();
    if (fin > simTime()) {
        if (!q->timer->isScheduled()) owner->scheduleAt(fin, q->timer);
        return;
    }
    cPacket *pkt = (cPacket *)(q->hi.isEmpty() ? q->lo.pop() : q->hi.pop());
    if (auto ip = dynamic_cast<InterestPacket *>(pkt)) ip->setHopDepartTimeSec(simTime().dbl());
    std::vector<std::pair<ByteClass, long>> parts;
    classifyBytes(pkt, parts);
    for (auto &p : parts) MetricsCollector::getInstance()->recordTx(p.first, p.second);
    owner->send(pkt, out);
    if (!q->hi.isEmpty() || !q->lo.isEmpty())
        owner->scheduleAt(ch->getTransmissionFinishTime(), q->timer);
}

void GateTx::clear() {
    for (Q *q : queues) {
        while (!q->hi.isEmpty()) delete q->hi.pop();
        while (!q->lo.isEmpty()) delete q->lo.pop();
        owner->cancelAndDelete(q->timer);
        delete q;
    }
    queues.clear();
}

static char kRedeliverTag;

bool handleLinkLoss(cSimpleModule *m, cMessage *msg, double rto) {
    auto *pk = dynamic_cast<cPacket *>(msg);
    if (!pk || !pk->hasBitError()) return false;
    if (dynamic_cast<CtrlPacket *>(pk) && std::string(pk->getName()) != "StatusBeacon") {
        // Reliable transport: the lost copy is sent again after one RTO and
        // its bytes are charged again.
        std::vector<std::pair<ByteClass, long>> parts;
        classifyBytes(pk, parts);
        for (auto &p : parts) MetricsCollector::getInstance()->recordTx(p.first, p.second);
        pk->setBitError(false);
        pk->setContextPointer(&kRedeliverTag);
        m->scheduleAt(simTime() + rto, pk);
        return true;
    }
    delete msg;
    return true;
}

bool takeRedelivery(cMessage *msg) {
    if (msg->getContextPointer() != &kRedeliverTag) return false;
    msg->setContextPointer(nullptr);
    return true;
}

bool isRouterModule(cModule *m) {
    return m && std::string(m->getNedTypeName()) == "ned.Router";
}

bool isConsumerModule(cModule *m) {
    return m && std::string(m->getNedTypeName()) == "ned.Consumer";
}

cModule *peerOfGate(cModule *self, int i) {
    cGate *g = self->gate("port$o", i);
    if (!g) return nullptr;
    cGate *end = g->getPathEndGate();
    return end ? end->getOwnerModule() : nullptr;
}

std::map<int, int> buildControlRoutes(cModule *self) {
    std::map<int, int> next;
    struct Item { cModule *m; int first; };
    std::queue<Item> q;
    std::set<cModule *> seen{self};
    int n = self->gateSize("port");
    for (int i = 0; i < n; i++) {
        cModule *p = peerOfGate(self, i);
        if (!p || seen.count(p)) continue;
        seen.insert(p);
        next[p->getId()] = i;
        if (isRouterModule(p)) q.push({p, i});
    }
    while (!q.empty()) {
        Item it = q.front(); q.pop();
        int pn = it.m->gateSize("port");
        for (int j = 0; j < pn; j++) {
            cModule *p = peerOfGate(it.m, j);
            if (!p || seen.count(p)) continue;
            seen.insert(p);
            next[p->getId()] = it.first;
            if (isRouterModule(p)) q.push({p, it.first});
        }
    }
    return next;
}

static void collect(cModule *m, const char *type, std::vector<cModule *> &out) {
    for (cModule::SubmoduleIterator it(m); !it.end(); ++it) {
        cModule *sub = *it;
        std::string t = sub->getNedTypeName();
        // Match our own NDN node types only (ned.<Type>), at any depth, so
        // nodes nested inside INET hosts (5G scenario) are found too.
        if (t == std::string("ned.") + type) out.push_back(sub);
        collect(sub, type, out);
    }
}

std::vector<cModule *> findModulesByType(cModule *any, const char *type) {
    std::vector<cModule *> out;
    collect(any->getSimulation()->getSystemModule(), type, out);
    return out;
}

} // namespace ndnpreencryption
