#include "Producer.h"

#include <cctype>
#include <cstring>

#include "Issuer.h"
#include "../utils/FhirCorpus.h"

namespace ndnpreencryption {

Define_Module(Producer);

void Producer::initialize(int stage) {
    if (stage == 0) {
        framework = par("framework").stdstringValue();
        prefix = par("contentPrefix").stdstringValue();
        secure = framework != "none";
        cpuFactor = par("cpuFactor").doubleValue();
        key = CryptoEngine::generateEd25519KeyPair();
        std::string dir = par("fhirCorpusDir").stdstringValue();
        if (!dir.empty()) {
            FhirCorpus &c = FhirCorpus::instance(dir);
            if (c.isLoaded() && c.totalLoaded() > 0) fhir.useCorpus(&c);
        }
        tx.init(this, "port", par("priorityQueueing").boolValue());
    } else if (secure) {
        auto *iss = check_and_cast<Issuer *>(getModuleByPath(par("issuerModulePath").stringValue()));
        ownerPk = iss->getOwnerPrePublicKey();
        issuerPk = iss->getSigningPublicKey();
        engine.configure(iss->getDid(), issuerPk, iss->getSealKey(), &status,
                         (size_t)par("sessionCapacity").intValue(),
                         par("replayWindow").doubleValue());
    }
}

std::string Producer::stripRecipient(const std::string &name) {
    size_t r = name.rfind("/r/");
    if (r == std::string::npos) return name;
    for (size_t i = r + 3; i < name.size(); i++)
        if (!std::isdigit((unsigned char)name[i])) return name;
    return name.substr(0, r);
}

DataPacket *Producer::contentFor(const std::string &base, double &cost) {
    cost = 0;
    auto it = repo.find(base);
    if (it != repo.end()) return it->second;
    std::string body = fhir.buildResource(base);
    if (body.empty()) body = "{\"resourceType\":\"Basic\",\"id\":\"" + base + "\"}";
    auto *d = new DataPacket("Data");
    d->setContentName(base.c_str());
    d->setPlainSize((int)body.size());
    d->setIsCritical(false);
    const CostModel &cm = CostModel::instance();
    if (secure) {
        Bytes dek;
        PreCapsule cap = UmbralPRE::encapsulate(ownerPk, dek);
        Bytes aad(base.begin(), base.end());
        AeadCiphertext ct = CryptoEngine::aesGcmEncrypt(dek, Bytes(body.begin(), body.end()), aad);
        d->setEncrypted(true);
        d->setCiphertext(CryptoEngine::toBase64Url(ct.ciphertext).c_str());
        d->setIv(CryptoEngine::toBase64Url(ct.iv).c_str());
        d->setTag(CryptoEngine::toBase64Url(ct.tag).c_str());
        d->setCapsuleE(CryptoEngine::toBase64Url(cap.E).c_str());
        d->setCapsuleV(CryptoEngine::toBase64Url(cap.V).c_str());
        d->setCapsuleS(CryptoEngine::toBase64Url(cap.s).c_str());
        std::string signedPart = base + "|" + d->getCiphertext() + "|" + d->getIv() + "|" + d->getTag() + "|" +
                                 d->getCapsuleE() + "|" + d->getCapsuleV() + "|" + d->getCapsuleS() + "|" +
                                 std::to_string(d->getPlainSize());
        d->setSignature(CryptoEngine::toBase64Url(CryptoEngine::ed25519Sign(
            key.privateKey, Bytes(signedPart.begin(), signedPart.end()))).c_str());
        d->setByteLength(kDataFixed + (long)base.size() + (long)body.size() + 12 + 16 +
                         (long)cap.wireSize() + 64);
        cost = cpuFactor * (cm.aesPerKiB() * body.size() / 1024.0 + cm.preEncapsulate() + cm.edSign());
    } else {
        d->setCiphertext(body.c_str());
        // extraDataBytes: diagnostic padding that gives plain NDN the size of protected Data
        d->setByteLength(kDataFixed + (long)base.size() + (long)body.size() + par("extraDataBytes").intValue());
    }
    repo[base] = d;
    generated++;
    return d;
}

void Producer::handleMessage(cMessage *msg) {
    if (tx.handleTimer(msg)) return;
    bool redelivered = takeRedelivery(msg);
    if (msg->isSelfMessage() && !redelivered) {
        cPacket *p = (cPacket *)msg;
        tx.send(p, p->getKind());
        return;
    }
    if (!redelivered && handleLinkLoss(this, msg)) return;
    if (auto ip = dynamic_cast<InterestPacket *>(msg)) {
        onInterest(ip, ip->getArrivalGate()->getIndex());
        delete ip;
        return;
    }
    if (dynamic_cast<VCListDeltaPacket *>(msg) || dynamic_cast<VCListSnapshotPacket *>(msg)) {
        onStatus((cPacket *)msg);
        delete msg;
        return;
    }
    delete msg;
}

void Producer::onStatus(cPacket *p) {
    if (framework != "didvc_producer" && framework != "didvc_key") return;
    const CostModel &cm = CostModel::instance();
    (void)cm;
    if (auto d = dynamic_cast<VCListDeltaPacket *>(p)) {
        if (status.applyDelta(StatusDelta::fromJson(d->getDeltaJson()), issuerPk) ==
            StatusList::ApplyResult::APPLIED)
            MetricsCollector::getInstance()->stateApplied(getId(), status.version(), simTime().dbl());
    } else if (auto s = dynamic_cast<VCListSnapshotPacket *>(p)) {
        if (status.applySnapshot(StatusSnapshot::fromJson(s->getSnapshotJson()), issuerPk) ==
            StatusList::ApplyResult::APPLIED)
            MetricsCollector::getInstance()->stateApplied(getId(), status.version(), simTime().dbl());
    }
}

void Producer::onInterest(InterestPacket *ip, int gate) {
    std::string name = ip->getContentName();
    std::string base = stripRecipient(name);
    // Key-split baseline: "<record>/KEY/r/<consumer>" asks for the
    // per-clinician key fragment only.
    bool isKey = base.size() > 4 && base.compare(base.size() - 4, 4, "/KEY") == 0;
    if (isKey) base.erase(base.size() - 4);
    if (base.rfind(prefix, 0) != 0) {
        auto *n = new NACKPacket("NACK");
        n->setContentName(name.c_str());
        n->setReason(0);
        n->setNonce(ip->getNonce());
        n->setByteLength(kNackBytes);
        tx.send(n, gate);
        return;
    }
    double cost = 0;
    DataPacket *tmpl = contentFor(base, cost);
    simtime_t start = std::max(simTime(), cpuFree);
    cPacket *out = nullptr;

    if (framework == "didvc_producer" || (framework == "didvc_key" && isKey)) {
        InterestView iv;
        iv.name = name;
        iv.requesterId = ip->getRequesterId();
        iv.nonceHex = ip->getNonceHex();
        iv.lifetimeMs = (int)(ip->getLifetime() * 1000);
        iv.signingTs = ip->getSigningTimestamp();
        iv.signatureB64 = ip->getSignatureValue();
        iv.presentationMode = ip->getPresentationMode();
        iv.didDocJson = ip->getDidDocJson();
        iv.vcJson = ip->getVcJson();
        iv.vcId = ip->getVcId();
        iv.breakGlass = ip->getBreakGlass();
        Decision dec = engine.evaluate(iv, kSimEpochBase + (long long)simTime().dbl());
        cost += cpuFactor * dec.modeledCpu;
        MetricsCollector::DecisionRecord rec;
        rec.t = simTime().dbl();
        rec.node = getId();
        rec.requester = iv.requesterId;
        rec.name = base;
        rec.verdict = (int)dec.verdict;
        rec.modeledCpu = dec.modeledCpu;
        rec.measuredCpu = dec.measuredCpu;
        rec.breakGlass = iv.breakGlass;
        rec.attack = ip->getAttack();
        rec.rule = dec.rule;
        if (dec.verdict == Verdict::GRANT) {
            PreCapsule cap{CryptoEngine::fromBase64Url(tmpl->getCapsuleE()),
                           CryptoEngine::fromBase64Url(tmpl->getCapsuleV()),
                           CryptoEngine::fromBase64Url(tmpl->getCapsuleS())};
            PreCFrag f;
            UmbralPRE::reencapsulate(dec.rk, cap, f);
            double rc = cpuFactor * CostModel::instance().cost(Stage::PRE_REENCAPSULATE);
            cost += rc;
            MetricsCollector::getInstance()->recordReencapsulation(rc);
            DataPacket *d = nullptr;
            if (isKey) {
                // Only the key material travels: capsule, fragment, signature.
                d = new DataPacket("KeyData");
                d->setEncrypted(true);
                d->setKeyOnly(true);
                d->setCapsuleE(tmpl->getCapsuleE());
                d->setCapsuleV(tmpl->getCapsuleV());
                d->setCapsuleS(tmpl->getCapsuleS());
                d->setByteLength(kDataFixed + (long)name.size() + 98 + (long)f.wireSize() + 64);
            } else {
                d = tmpl->dup();
                d->setByteLength(tmpl->getByteLength() + (long)(name.size() - base.size()) + (long)f.wireSize());
            }
            d->setContentName(name.c_str());
            d->setCfragE1(CryptoEngine::toBase64Url(f.E1).c_str());
            d->setCfragV1(CryptoEngine::toBase64Url(f.V1).c_str());
            d->setCfragX(CryptoEngine::toBase64Url(f.X).c_str());
            d->setRecipient(ip->getOriginConsumer());
            d->setPitToken(ip->getNonce());
            d->setIsCritical(iv.breakGlass);
            // A personalized copy is useful to one clinician only; caching it
            // would let routers serve it after the clinician is revoked.
            d->setNoCache(true);
            out = d;
        } else {
            auto *n = new NACKPacket("NACK");
            n->setContentName(name.c_str());
            n->setReason(verdictToNackReason(dec.verdict));
            n->setNonce(ip->getNonce());
            n->setDetails(verdictName(dec.verdict));
            n->setByteLength(kNackBytes);
            out = n;
            denied++;
        }
        rec.decisionDelay = (start - simTime()).dbl() + cost;
        MetricsCollector::getInstance()->recordDecision(rec);
    } else {
        out = tmpl->dup();
    }
    cpuFree = start + cost;
    out->setKind(gate);
    served++;
    scheduleAt(cpuFree, out);
}

void Producer::finish() {
    recordScalar("served", served);
    recordScalar("generated", generated);
    recordScalar("denied", denied);
    for (auto &kv : repo) delete kv.second;
    repo.clear();
    tx.clear();
}

} // namespace ndnpreencryption
