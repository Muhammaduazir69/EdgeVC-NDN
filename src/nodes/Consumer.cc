#include "Consumer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

#include "Issuer.h"
#include "Producer.h"
#include "../security/EnforcementEngine.h"

namespace ndnpreencryption {

Define_Module(Consumer);

namespace {
std::vector<double> zipfCdf(size_t n, double a) {
    std::vector<double> c(n);
    double s = 0;
    for (size_t i = 0; i < n; i++) { s += 1.0 / std::pow((double)(i + 1), a); c[i] = s; }
    for (auto &x : c) x /= s;
    return c;
}
std::string stripSuffix(const std::string &name) {
    size_t r = name.rfind("/r/");
    return r == std::string::npos ? name : name.substr(0, r);
}
} // namespace

void Consumer::initialize(int stage) {
    if (stage == 0) {
        framework = par("framework").stdstringValue();
        secure = framework != "none";
        role = par("userRole").stdstringValue();
        unit = par("unit").stdstringValue();
        clearance = par("clearance").intValue();
        organization = par("organization").stdstringValue();
        rate = par("requestRate").doubleValue();
        preferredShare = par("preferredShare").doubleValue();
        zipf = par("zipfAlpha").doubleValue();
        breakGlassRate = par("breakGlassRate").doubleValue();
        lifetime = par("interestLifetime").doubleValue();
        compact = par("compactPresentation").boolValue() &&
                  (framework == "didvc" || framework == "didvc_producer" || framework == "didvc_key");
        clientCacheSize = par("clientCacheSize").intValue();
        stopOnRevocation = par("stopOnRevocation").boolValue();
        presentationRefresh = par("presentationRefresh").doubleValue();
        attackType = par("attackType").stdstringValue();
        attackRate = par("attackRate").doubleValue();
        cpuFactor = par("cpuFactor").doubleValue();

        sigKey = CryptoEngine::generateEd25519KeyPair();
        preKey = UmbralPRE::keygen();
        did = DID::fromEd25519PublicKey(sigKey.publicKey);
        DIDDocument doc;
        doc.did = did;
        doc.controller = did;
        doc.signingPublicKey = sigKey.publicKey;
        doc.keyAgreementPublicKey = preKey.pk;
        doc.created = kSimEpochBase;
        didDocJson = doc.toJson();
        didDocFp = CryptoEngine::toBase64Url(CryptoEngine::sha256(didDocJson));

        catalog = fhir.buildCatalog(par("catalogSize").intValue(), par("contentPrefix").stdstringValue());
        // Clinical locality: routine work concerns the clinician's own unit, so
        // the preferred set is the permitted records of that unit; roles whose
        // work spans units (pharmacy, front office) use all permitted records.
        SubjectAttrs me{role, unit, clearance};
        std::vector<std::string> permitted;
        for (const auto &n : catalog) {
            ResourceAttrs ra = ResourceAttrs::fromName(n);
            if (AccessPolicy::evaluate(me, ra, false).empty()) continue;
            permitted.push_back(n);
            if (ra.unit == unit) preferred.push_back(n);
        }
        if (preferred.empty()) preferred = permitted;
        cdfAll = zipfCdf(catalog.size(), zipf);
        if (!preferred.empty()) cdfPref = zipfCdf(preferred.size(), zipf);
        tx.init(this, "port", par("priorityQueueing").boolValue());
        return;
    }
    issuer = dynamic_cast<Issuer *>(getModuleByPath(par("issuerModulePath").stringValue()));
    if (issuer) issuerId = issuer->getId();
    if (secure) {
        auto *prod = check_and_cast<Producer *>(getModuleByPath(par("producerModulePath").stringValue()));
        producerPk = prod->getSigningPublicKey();
    }
    if (attackType != "none") {
        std::string v = par("attackVictim").stdstringValue();
        if (!v.empty()) victim = dynamic_cast<Consumer *>(getModuleByPath(v.c_str()));
    }
    reqTimer = new cMessage("request");
    atkTimer = new cMessage("attack");
    sweepTimer = new cMessage("sweep");
    enrollRetry = new cMessage("enrollRetry");
    scheduleAt(0.25, sweepTimer);
    double start = par("startTime").doubleValue() + uniform(0, 0.5);
    bool legit = attackType == "none";
    bool needsEnrollment = secure && (legit || attackType == "tampered_vc");
    if (needsEnrollment) scheduleAt(start, enrollRetry);
    else if (legit) { enrolled = true; scheduleAt(start + exponential(1.0 / rate), reqTimer); }
    else if (attackType == "tampered_vc") enrolled = true;  // no access control: the insider needs no credential
    if (!legit && attackRate > 0) scheduleAt(par("attackStart").doubleValue() + exponential(1.0 / attackRate), atkTimer);
}

void Consumer::handleMessage(cMessage *msg) {
    if (tx.handleTimer(msg)) return;
    bool redelivered = takeRedelivery(msg);
    if (msg == reqTimer) {
        generateInterest();
        scheduleAt(simTime() + exponential(1.0 / rate), reqTimer);
        return;
    }
    if (msg == atkTimer) {
        generateAttack();
        scheduleAt(simTime() + exponential(1.0 / attackRate), atkTimer);
        return;
    }
    if (msg == sweepTimer) {
        sweepTimeouts();
        scheduleAt(simTime() + 0.25, sweepTimer);
        return;
    }
    if (msg == enrollRetry) {
        if (!enrolled) { enroll(); scheduleAt(simTime() + 2.0, enrollRetry); }
        return;
    }
    if (msg->isSelfMessage() && !redelivered) { // signed packet leaving after CPU time
        tx.send((cPacket *)msg, 0);
        return;
    }
    if (!redelivered && handleLinkLoss(this, msg)) return;
    if (auto r = dynamic_cast<VCIssueResponse *>(msg)) onIssueResponse(r);
    else if (auto d = dynamic_cast<DataPacket *>(msg)) onData(d);
    else if (auto n = dynamic_cast<NACKPacket *>(msg)) onNack(n);
    delete msg;
}

void Consumer::sendAfterCpu(cPacket *p, double cost) {
    simtime_t start = std::max(simTime(), cpuFree);
    cpuFree = start + cost;
    if (cost <= 0) tx.send(p, 0);
    else scheduleAt(cpuFree, p);
}

void Consumer::enroll() {
    auto *r = new VCIssueRequest("VCIssueRequest");
    int nonce = intuniform(1, 0x7fffffff);
    std::string ppk = CryptoEngine::toBase64Url(preKey.pk);
    r->setSrcId(getId());
    r->setDstId(issuerId);
    r->setRequesterId(did.c_str());
    if (framework.rfind("didvc", 0) == 0) r->setDidDocJson(didDocJson.c_str());
    r->setSigningPublicKey(CryptoEngine::toBase64Url(sigKey.publicKey).c_str());
    r->setPrePublicKey(ppk.c_str());
    r->setRequestedRole(role.c_str());
    r->setRequestedUnit(unit.c_str());
    r->setOrganization(organization.c_str());
    r->setClearance(clearance);
    r->setNonce(nonce);
    std::string canon = did + "|" + role + "|" + unit + "|" + organization + "|" +
                        std::to_string(clearance) + "|" + std::to_string(nonce) + "|" + ppk;
    r->setSignatureValue(CryptoEngine::toBase64Url(
        CryptoEngine::ed25519Sign(sigKey.privateKey, Bytes(canon.begin(), canon.end()))).c_str());
    r->setByteLength(24 + (long)did.size() + (long)std::strlen(r->getDidDocJson()) + 32 + 33 +
                     (long)(role.size() + unit.size() + organization.size()) + 8 + 64);
    tx.send(r, 0);
}

void Consumer::onIssueResponse(VCIssueResponse *r) {
    if (!r->getSuccess()) return;   // refused (revoked or suspended holder): keep what we have
    if (framework.rfind("didvc", 0) == 0) {
        vcJson = r->getVcJson();
        vcId = VerifiableCredential::fromJson(vcJson).id;
        needFull = true;
    }
    bool first = !enrolled;
    enrolled = true;
    if (first && attackType == "none") scheduleAt(simTime() + exponential(1.0 / rate), reqTimer);
}

std::string Consumer::drawName(bool usePreferred) {
    const auto &pool = (usePreferred && !preferred.empty()) ? preferred : catalog;
    const auto &cdf = (usePreferred && !preferred.empty()) ? cdfPref : cdfAll;
    double u = uniform(0.0, 1.0);
    size_t i = std::lower_bound(cdf.begin(), cdf.end(), u) - cdf.begin();
    return pool[std::min(i, pool.size() - 1)];
}

void Consumer::signInto(InterestPacket *ip, const Bytes &sk, const std::string &fp) {
    std::string in = interestSigningInput(stripSuffix(ip->getContentName()) == ip->getContentName()
                                              ? ip->getContentName() : ip->getContentName(),
                                          ip->getRequesterId(), ip->getNonceHex(),
                                          (int)(ip->getLifetime() * 1000), ip->getSigningTimestamp(),
                                          ip->getVcId(), ip->getBreakGlass(), fp);
    ip->setSignatureValue(CryptoEngine::toBase64Url(
        CryptoEngine::ed25519Sign(sk, Bytes(in.begin(), in.end()))).c_str());
}

InterestPacket *Consumer::buildInterest(const std::string &base, bool bg, bool forceFull) {
    std::string name = base;
    bool keyName = base.size() > 4 && base.compare(base.size() - 4, 4, "/KEY") == 0;
    if (framework == "didvc_producer" || (framework == "didvc_key" && keyName))
        name += "/r/" + std::to_string(getId());
    auto *ip = new InterestPacket("Interest");
    ip->setContentName(name.c_str());
    ip->setNonce(intuniform(1, 0x7fffffff));
    ip->setLifetime(lifetime);
    ip->setBreakGlass(bg);
    ip->setOriginConsumer(getId());
    long bytes = kInterestFixed + (long)name.size();
    if (secure) {
        char hex[33];
        std::snprintf(hex, sizeof(hex), "%08x%08x%08x%08x", (unsigned)intuniform(0, 0x7fffffff),
                      (unsigned)intuniform(0, 0x7fffffff), (unsigned)intuniform(0, 0x7fffffff),
                      (unsigned)intuniform(0, 0x7fffffff));
        ip->setRequesterId(did.c_str());
        ip->setNonceHex(hex);
        ip->setSigningTimestamp(kSimEpochBase + (long long)simTime().dbl());
        bytes += (long)did.size() + kInterestSigFixed;
        std::string fp;
        if (framework.rfind("didvc", 0) == 0) {
            fp = didDocFp;
            bool refreshDue = presentationRefresh > 0 && lastFull >= 0 &&
                              simTime() - lastFull > presentationRefresh;
            bool full = !compact || needFull || forceFull || refreshDue;
            ip->setVcId(vcId.c_str());
            if (full) {
                ip->setPresentationMode(PRES_FULL);
                ip->setDidDocJson(didDocJson.c_str());
                ip->setVcJson(vcJson.c_str());
                bytes += (long)(didDocJson.size() + vcJson.size() + vcId.size()) + 4;
                needFull = false;
                lastFull = simTime();
            } else {
                ip->setPresentationMode(PRES_COMPACT);
                bytes += (long)vcId.size() + 4;
            }
        }
        signInto(ip, sigKey.privateKey, fp);
    }
    // extraInterestBytes: diagnostic padding (plain NDN given the size of a signed Interest)
    ip->setByteLength(bytes + par("extraInterestBytes").intValue());
    return ip;
}

long Consumer::track(InterestPacket *ip, const std::string &base, bool expected, bool attack,
                     const std::string &atype) {
    MetricsCollector::InterestRecord r;
    r.consumer = getId();
    r.requester = did;
    r.holderActive = !secure || attack || (issuer && issuer->holderEnrolledAndActive(did));
    r.role = role;
    r.unit = unit;
    r.tSend = simTime().dbl();
    r.name = base;
    r.sensitivity = ResourceAttrs::fromName(base).sensitivity;
    r.expected = expected;
    r.attack = attack;
    r.attackType = atype;
    r.breakGlass = ip->getBreakGlass();
    if (r.breakGlass && !attack) {
        SubjectAttrs me{role, unit, clearance};
        ResourceAttrs ra = ResourceAttrs::fromName(base);
        bool routine = !AccessPolicy::evaluate(me, ra, false).empty();
        bool withBg = !AccessPolicy::evaluate(me, ra, true).empty();
        r.bgScope = !routine && withBg && r.holderActive;
        r.bgUnqualified = !withBg;
    }
    r.presentation = ip->getPresentationMode();
    r.interestBytes = (int)ip->getByteLength();
    long id = MetricsCollector::getInstance()->newInterest(r);
    pending[ip->getContentName()].push_back({id, simTime(), ip->getLifetime(), ip->getNonce(), base,
                                             ip->getBreakGlass(), 0});
    sent++;
    return id;
}

void Consumer::touchLocal(const std::string &name) {
    if (clientCacheSize <= 0) return;
    auto it = std::find(localLru.begin(), localLru.end(), name);
    if (it != localLru.end()) localLru.erase(it);
    else localSet.insert(name);
    localLru.push_front(name);
    while ((int)localLru.size() > clientCacheSize) { localSet.erase(localLru.back()); localLru.pop_back(); }
}

void Consumer::generateInterest() {
    if (!enrolled || stopped || simTime() < backoffUntil) return;
    std::string base = drawName(uniform(0.0, 1.0) < preferredShare);
    bool bg = breakGlassRate > 0 && uniform(0.0, 1.0) < breakGlassRate;
    // A record already decrypted on the device is reread locally.
    if (clientCacheSize > 0 && localSet.count(base)) {
        touchLocal(base);
        MetricsCollector::getInstance()->recordLocalHit();
        return;
    }
    SubjectAttrs me{role, unit, clearance};
    bool expected = !AccessPolicy::evaluate(me, ResourceAttrs::fromName(base), bg).empty() &&
                    (!secure || (issuer && issuer->holderEnrolledAndActive(did)));
    if (framework == "didvc_key") {
        // Key-split: the consumer-agnostic Data comes from any cache, the
        // per-clinician key fragment from the producer, which decides.
        InterestPacket *key = buildInterest(base + "/KEY", bg, false);
        auto *content = new InterestPacket("Interest");
        content->setContentName(base.c_str());
        content->setNonce(intuniform(1, 0x7fffffff));
        content->setLifetime(lifetime);
        content->setOriginConsumer(getId());
        content->setByteLength(kInterestFixed + (long)base.size());
        long rec = track(key, base, expected, false, "");
        pending[key->getContentName()].back().part = 2;
        pending[base].push_back({rec, simTime(), lifetime, content->getNonce(), base, bg, 1});
        splits[rec] = KeySplit();
        sendAfterCpu(content, 0.0);
        sendAfterCpu(key, cpuFactor * CostModel::instance().edSign());
        return;
    }
    InterestPacket *ip = buildInterest(base, bg, false);
    track(ip, base, expected, false, "");
    delete lastSent;
    lastSent = ip->dup();
    sendAfterCpu(ip, secure ? cpuFactor * CostModel::instance().edSign() : 0.0);
}

void Consumer::generateAttack() {
    if (!victim) return;
    const bool dv = framework.rfind("didvc", 0) == 0;
    std::string base = victim->preferred.empty() ? drawName(false)
                                                 : victim->preferred[intuniform(0, (int)victim->preferred.size() - 1)];
    if (attackType == "tampered_vc" && !victim->preferred.empty()) {
        // An escalation attempt targets only records the insider's genuine
        // attributes do not permit; otherwise a success would be legitimate.
        SubjectAttrs me{role, unit, clearance};
        for (int k = 0; k < 64 && !AccessPolicy::evaluate(me, ResourceAttrs::fromName(base), false).empty(); k++)
            base = victim->preferred[intuniform(0, (int)victim->preferred.size() - 1)];
        if (!AccessPolicy::evaluate(me, ResourceAttrs::fromName(base), false).empty()) return;
    }
    InterestPacket *ip = nullptr;
    std::string atype = attackType;

    if (attackType == "replay") {
        const InterestPacket *lp = victim->peekLastInterest();
        if (!lp) return;
        ip = lp->dup();
        base = stripSuffix(ip->getContentName());
    } else if (attackType == "no_credential") {
        ip = new InterestPacket("Interest");
        std::string name = base + (framework == "didvc_producer" ? "/r/" + std::to_string(getId()) : "");
        ip->setContentName(name.c_str());
        ip->setNonce(intuniform(1, 0x7fffffff));
        ip->setLifetime(lifetime);
        ip->setRequesterId("anonymous");
        ip->setByteLength(kInterestFixed + (long)name.size());
    } else {
        // Every remaining attack signs with the attacker's own key.
        ip = buildInterest(base, false, true);
        std::string fp = didDocFp;
        if (attackType == "forged_vc" && dv) {
            Ed25519KeyPair fake = CryptoEngine::generateEd25519KeyPair();
            VerifiableCredential vc = VerifiableCredential::fromJson(victim->getVcJson());
            vc.subject.id = did;
            vc.subject.reEncryptionKey = CryptoEngine::toBase64Url(CryptoEngine::randomBytes(121));
            vc.sign(fake.privateKey);
            std::string j = vc.toJson();
            ip->setVcJson(j.c_str());
            ip->setVcId(vc.id.c_str());
        } else if (attackType == "stolen_vc") {
            if (dv) {
                ip->setVcJson(victim->getVcJson().c_str());
                ip->setVcId(VerifiableCredential::fromJson(victim->getVcJson()).id.c_str());
            } else {
                ip->setRequesterId(victim->getDid().c_str());
                fp = "";
            }
        } else if (attackType == "did_spoof") {
            ip->setRequesterId(victim->getDid().c_str());
            if (dv) {
                ip->setVcJson(victim->getVcJson().c_str());
                ip->setVcId(VerifiableCredential::fromJson(victim->getVcJson()).id.c_str());
            } else fp = "";
        } else if (attackType == "tampered_vc") {
            if (!enrolled) { delete ip; return; }
            if (dv) {
                std::string j = vcJson;
                auto rep = [&](const std::string &a, const std::string &b) {
                    size_t p = j.find(a);
                    if (p != std::string::npos) j.replace(p, a.size(), b);
                };
                rep("\"role\":\"" + role + "\"", "\"role\":\"Attending\"");
                rep("\"unit\":\"" + unit + "\"", "\"unit\":\"" + ResourceAttrs::fromName(base).unit + "\"");
                rep("\"clearance\":" + std::to_string(clearance), "\"clearance\":4");
                ip->setVcJson(j.c_str());
            } else {
                atype = "privilege_escalation";
            }
        } else if (attackType == "forged_vc") {
            // abac/scbac analogue: an identity the authority never enrolled.
            fp = "";
        }
        if (!dv) fp = "";
        signInto(ip, sigKey.privateKey, fp);
        long bytes = kInterestFixed + (long)std::strlen(ip->getContentName()) +
                     (long)std::strlen(ip->getRequesterId()) + kInterestSigFixed;
        if (ip->getPresentationMode() == PRES_FULL)
            bytes += (long)(std::strlen(ip->getDidDocJson()) + std::strlen(ip->getVcJson()) +
                            std::strlen(ip->getVcId())) + 4;
        ip->setByteLength(bytes);
    }
    ip->setAttack(true);
    ip->setOriginConsumer(getId());
    track(ip, base, false, true, atype);
    sendAfterCpu(ip, 0.0);
}

void Consumer::onData(DataPacket *d) {
    std::string name = d->getContentName();
    auto it = pending.find(name);
    if (it == pending.end() || it->second.empty()) return;
    // A personalized copy carries the PIT token (nonce) of the request it
    // answers. An unpersonalized Data (plain NDN, key-split content) satisfies
    // every outstanding request for the name; each keeps its own waiting time.
    std::vector<Pending> waiting;
    if (d->getPitToken() != 0) {
        auto &q = it->second;
        auto pos = q.begin();
        while (pos != q.end() && pos->nonce != d->getPitToken()) ++pos;
        if (pos == q.end()) return;          // request already timed out or answered
        waiting.push_back(*pos);
        q.erase(pos);
        if (q.empty()) pending.erase(it);
    } else {
        waiting.assign(it->second.begin(), it->second.end());
        pending.erase(it);
    }
    std::vector<Pending> plain;
    for (const Pending &p : waiting) {
        if (p.part == 0) { plain.push_back(p); continue; }
        auto sp = splits.find(p.rec);
        if (sp == splits.end() || sp->second.done) continue;
        DataPacket *&slot = (p.part == 1) ? sp->second.content : sp->second.key;
        if (!slot) slot = d->dup();
        if (sp->second.content && sp->second.key) {
            sp->second.done = true;
            deliver({p}, sp->second.content, sp->second.key);
            delete sp->second.content;
            delete sp->second.key;
            splits.erase(sp);
        }
    }
    if (!plain.empty()) deliver(plain, d, d);
}

void Consumer::deliver(const std::vector<Pending> &waiting, DataPacket *d, DataPacket *k) {
    bool ok = true;
    double cost = 0;
    std::string base = waiting.front().base;
    if (secure) {
        ok = false;
        std::string signedPart = base + "|" + d->getCiphertext() + "|" + d->getIv() + "|" + d->getTag() + "|" +
                                 d->getCapsuleE() + "|" + d->getCapsuleV() + "|" + d->getCapsuleS() + "|" +
                                 std::to_string(d->getPlainSize());
        bool sigOk = CryptoEngine::ed25519Verify(producerPk, Bytes(signedPart.begin(), signedPart.end()),
                                                 CryptoEngine::fromBase64Url(d->getSignature()));
        if (sigOk && std::strlen(k->getCfragE1()) > 0) {
            PreCapsule cap{CryptoEngine::fromBase64Url(d->getCapsuleE()),
                           CryptoEngine::fromBase64Url(d->getCapsuleV()),
                           CryptoEngine::fromBase64Url(d->getCapsuleS())};
            PreCFrag f{CryptoEngine::fromBase64Url(k->getCfragE1()),
                       CryptoEngine::fromBase64Url(k->getCfragV1()),
                       CryptoEngine::fromBase64Url(k->getCfragX())};
            Bytes dek;
            if (UmbralPRE::decapsulateFrag(preKey.sk, cap, f, dek)) {
                AeadCiphertext ct{CryptoEngine::fromBase64Url(d->getIv()),
                                  CryptoEngine::fromBase64Url(d->getCiphertext()),
                                  CryptoEngine::fromBase64Url(d->getTag())};
                try {
                    Bytes plainText = CryptoEngine::aesGcmDecrypt(dek, ct, Bytes(base.begin(), base.end()));
                    ok = (int)plainText.size() == d->getPlainSize();
                } catch (...) { ok = false; }
            }
        }
        const CostModel &cm = CostModel::instance();
        cost = cpuFactor * (cm.edVerify() + cm.preDecapsulate() + cm.aesPerKiB() * d->getPlainSize() / 1024.0);
    }
    simtime_t start = std::max(simTime(), cpuFree);
    cpuFree = start + cost;
    for (const Pending &p : waiting) {
        if (ok) dataOk++; else decryptFail++;
        MetricsCollector::getInstance()->interestOutcome(p.rec, 0, -1, cpuFree.dbl(), ok, d->getPlainSize());
    }
    if (ok && attackType == "none") touchLocal(base);
}

void Consumer::onNack(NACKPacket *n) {
    std::string name = n->getContentName();
    nacks++;
    // A NACK answers one specific Interest: match it by nonce (the edge
    // echoes the consumer's nonce), so that it never clears an older request
    // for the same name that is still being served.
    auto it = pending.find(name);
    if (it == pending.end() || it->second.empty()) return;
    auto &q = it->second;
    auto pos = q.begin();
    while (pos != q.end() && pos->nonce != n->getNonce()) ++pos;
    if (pos == q.end()) pos = q.begin();
    Pending p = *pos;
    q.erase(pos);
    if (q.empty()) pending.erase(it);
    int reason = n->getReason();
    if (reason == 6 && attackType == "none") {
        // The edge holds no session for us: resend this request at once with
        // the full presentation; the request keeps its original send time.
        needFull = true;
        InterestPacket *ip = buildInterest(p.part == 2 ? p.base + "/KEY" : p.base, p.bg, true);
        pending[ip->getContentName()].push_back({p.rec, p.sent, p.lifetime, ip->getNonce(), p.base, p.bg, p.part});
        sendAfterCpu(ip, cpuFactor * CostModel::instance().edSign());
        return;
    }
    if (p.part != 0) {
        auto sp = splits.find(p.rec);
        if (sp != splits.end()) {
            if (sp->second.done) return;
            sp->second.done = true;
            delete sp->second.content; delete sp->second.key;
            splits.erase(sp);
        }
    }
    MetricsCollector::getInstance()->interestOutcome(p.rec, 1, reason, simTime().dbl(), false, 0);
    if (attackType != "none") return;
    if (stopOnRevocation) {                                   // honest client
        if (reason == 4) stopped = true;                      // revoked: stop working
        if (reason == 3) backoffUntil = simTime() + 30.0;     // suspended: probe again later
    }
    if (reason == 5) enroll();
}

void Consumer::sweepTimeouts() {
    for (auto it = pending.begin(); it != pending.end();) {
        auto &q = it->second;
        while (!q.empty() && q.front().sent + q.front().lifetime <= simTime()) {
            const Pending &p = q.front();
            bool record = true;
            if (p.part != 0) {
                auto sp = splits.find(p.rec);
                if (sp == splits.end() || sp->second.done) record = false;
                else { sp->second.done = true; delete sp->second.content; delete sp->second.key; splits.erase(sp); }
            }
            if (record) {
                MetricsCollector::getInstance()->interestOutcome(p.rec, 2, -1, (p.sent + p.lifetime).dbl(), false, 0);
                timeouts++;
            }
            q.pop_front();
        }
        if (q.empty()) it = pending.erase(it);
        else ++it;
    }
}

void Consumer::finish() {
    recordScalar("sent", sent);
    recordScalar("dataOk", dataOk);
    recordScalar("nacks", nacks);
    recordScalar("timeouts", timeouts);
    recordScalar("decryptFail", decryptFail);
    recordScalar("preferredCatalog", (double)preferred.size());
    delete lastSent;
    lastSent = nullptr;
    for (auto &kv : splits) { delete kv.second.content; delete kv.second.key; }
    splits.clear();
    cancelAndDelete(reqTimer);
    cancelAndDelete(atkTimer);
    cancelAndDelete(sweepTimer);
    cancelAndDelete(enrollRetry);
    reqTimer = atkTimer = sweepTimer = enrollRetry = nullptr;
    tx.clear();
}

} // namespace ndnpreencryption
