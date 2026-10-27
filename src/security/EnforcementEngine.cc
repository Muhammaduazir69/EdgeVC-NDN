#include "EnforcementEngine.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <sstream>
#include <vector>

namespace ndnpreencryption {

namespace {
using Clock = std::chrono::high_resolution_clock;

double since(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

double medianOf(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v.empty() ? 0.0 : v[v.size() / 2];
}

double timeMedian(int n, const std::function<void()> &fn) {
    std::vector<double> s;
    s.reserve(n);
    for (int i = 0; i < 20; i++) fn();     // warm caches
    for (int i = 0; i < n; i++) {
        auto t0 = Clock::now();
        fn();
        s.push_back(since(t0));
    }
    return medianOf(s);
}
} // namespace

const char *stageName(Stage s) {
    switch (s) {
        case Stage::DID_PARSE_THUMBPRINT: return "did_parse_thumbprint";
        case Stage::INTEREST_SIG_VERIFY:  return "interest_sig_verify";
        case Stage::VC_PARSE_VERIFY:      return "vc_parse_verify";
        case Stage::CLAIMS_STATUS_POLICY: return "claims_status_policy";
        case Stage::REKEY_UNSEAL:         return "rekey_unseal";
        case Stage::SESSION_LOOKUP:       return "session_lookup";
        case Stage::PRE_REENCAPSULATE:    return "pre_reencapsulate";
        case Stage::DECISION_SIGN:        return "decision_sign";
        case Stage::DECISION_VERIFY:      return "decision_verify";
        case Stage::POLICY_ONLY:          return "policy_only";
        default: return "?";
    }
}

int verdictToNackReason(Verdict v) {
    switch (v) {
        case Verdict::GRANT: return -1;
        case Verdict::DENY_SUSPENDED: return 3;
        case Verdict::DENY_REVOKED: return 4;
        case Verdict::DENY_EXPIRED: return 5;
        case Verdict::NEED_PRESENTATION: return 6;
        case Verdict::DENY_REPLAY: return 8;
        default: return 2;
    }
}

const char *verdictName(Verdict v) {
    switch (v) {
        case Verdict::GRANT: return "grant";
        case Verdict::DENY_SIGNATURE: return "deny_signature";
        case Verdict::DENY_SUSPENDED: return "deny_suspended";
        case Verdict::DENY_REVOKED: return "deny_revoked";
        case Verdict::DENY_EXPIRED: return "deny_expired";
        case Verdict::NEED_PRESENTATION: return "need_presentation";
        case Verdict::DENY_REPLAY: return "deny_replay";
        case Verdict::DENY_POLICY: return "deny_policy";
        case Verdict::DENY_FORGED: return "deny_forged";
        case Verdict::DENY_BINDING: return "deny_binding";
        case Verdict::DENY_NO_CREDENTIAL: return "deny_no_credential";
    }
    return "?";
}

std::string interestSigningInput(const std::string &name, const std::string &requesterId,
                                 const std::string &nonceHex, int lifetimeMs,
                                 long long ts, const std::string &vcId,
                                 bool breakGlass, const std::string &keyFingerprint) {
    std::string s = "NDN-INTEREST-v2\n";
    s += name; s += '\n';
    s += requesterId; s += '\n';
    s += nonceHex; s += '\n';
    s += std::to_string(lifetimeMs); s += '\n';
    s += std::to_string(ts); s += '\n';
    s += vcId; s += '\n';
    s += breakGlass ? "1" : "0"; s += '\n';
    s += keyFingerprint;
    return s;
}

// ---------------------------------------------------------------- engine

void EnforcementEngine::configure(const std::string &iDid, const Bytes &iPk,
                                  const Bytes &sk, const StatusList *st,
                                  size_t cap, double win) {
    issuerDid = iDid;
    issuerPk = iPk;
    sealKey = sk;
    status = st;
    capacity = cap;
    replayWindow = win;
}

std::string EnforcementEngine::sealReKey(const Bytes &key, const PreReKey &rk) {
    Bytes aad = {'R', 'K', '-', 'S', 'E', 'A', 'L'};
    AeadCiphertext ct = CryptoEngine::aesGcmEncrypt(key, rk.serialize(), aad);
    Bytes out = ct.iv;
    out.insert(out.end(), ct.ciphertext.begin(), ct.ciphertext.end());
    out.insert(out.end(), ct.tag.begin(), ct.tag.end());
    return CryptoEngine::toBase64Url(out);
}

bool EnforcementEngine::unsealReKey(const Bytes &key, const std::string &sealed, PreReKey &rk) {
    Bytes raw = CryptoEngine::fromBase64Url(sealed);
    if (raw.size() < 12 + 16 + 1) return false;
    AeadCiphertext ct;
    ct.iv.assign(raw.begin(), raw.begin() + 12);
    ct.tag.assign(raw.end() - 16, raw.end());
    ct.ciphertext.assign(raw.begin() + 12, raw.end() - 16);
    Bytes aad = {'R', 'K', '-', 'S', 'E', 'A', 'L'};
    try {
        rk = PreReKey::deserialize(CryptoEngine::aesGcmDecrypt(key, ct, aad));
    } catch (...) {
        return false;
    }
    return rk.rk.size() == 32;
}

bool EnforcementEngine::replaySeen(const std::string &req, const std::string &nonce,
                                   long long ts, long long now) {
    while (!nonceAge.empty() && nonceAge.front().first < now - (long long)replayWindow) {
        nonceSet.erase(nonceAge.front().second);
        nonceAge.pop_front();
    }
    if (ts < now - (long long)replayWindow || ts > now + 5) return true;
    std::string key = req + "|" + nonce;
    if (!nonceSet.insert(key).second) return true;
    nonceAge.emplace_back(ts, key);
    return false;
}

void EnforcementEngine::storeSession(const Session &s) {
    auto it = sessionIndex.find(s.did);
    if (it != sessionIndex.end()) {
        lru.erase(it->second.second);
        sessionIndex.erase(it);
    }
    lru.push_front(s.did);
    sessionIndex.emplace(s.did, std::make_pair(s, lru.begin()));
    while (sessionIndex.size() > capacity) {
        sessionIndex.erase(lru.back());
        lru.pop_back();
        evictions++;
    }
}

Decision EnforcementEngine::evaluate(const InterestView &iv, long long now) {
    Decision d;
    const CostModel &cm = CostModel::instance();
    auto t0 = Clock::now();
    auto charge = [&](Stage s) { d.modeledCpu += cm.cost(s); d.stages++; };
    auto finish = [&](Verdict v) { d.verdict = v; d.measuredCpu = since(t0); return d; };

    ResourceAttrs res = ResourceAttrs::fromName(iv.name);
    Bytes sig = CryptoEngine::fromBase64Url(iv.signatureB64);

    if (iv.presentationMode == 2) {
        charge(Stage::SESSION_LOOKUP);
        auto it = sessionIndex.find(iv.requesterId);
        if (it == sessionIndex.end() || it->second.first.vcId != iv.vcId)
            return finish(Verdict::NEED_PRESENTATION);
        lru.splice(lru.begin(), lru, it->second.second);
        const Session &s = it->second.first;
        charge(Stage::INTEREST_SIG_VERIFY);
        std::string in = interestSigningInput(iv.name, iv.requesterId, iv.nonceHex,
                                              iv.lifetimeMs, iv.signingTs, iv.vcId,
                                              iv.breakGlass, s.keyFingerprint);
        if (!CryptoEngine::ed25519Verify(s.signingPk, Bytes(in.begin(), in.end()), sig))
            return finish(Verdict::DENY_SIGNATURE);
        if (replaySeen(iv.requesterId, iv.nonceHex, iv.signingTs, now))
            return finish(Verdict::DENY_REPLAY);
        charge(Stage::CLAIMS_STATUS_POLICY);
        d.subjectRole = s.subject.role;
        d.subjectUnit = s.subject.unit;
        d.statusIndex = s.statusIndex;
        if (now < s.validFrom || now > s.validUntil) return finish(Verdict::DENY_EXPIRED);
        CredStatus st = status ? status->lookup(s.statusIndex) : CredStatus::ACTIVE;
        if (st == CredStatus::REVOKED) return finish(Verdict::DENY_REVOKED);
        if (st == CredStatus::SUSPENDED) return finish(Verdict::DENY_SUSPENDED);
        d.rule = AccessPolicy::evaluate(s.subject, res, iv.breakGlass);
        if (d.rule.empty()) return finish(Verdict::DENY_POLICY);
        d.rk = s.rk;
        return finish(Verdict::GRANT);
    }

    // Full presentation.
    charge(Stage::DID_PARSE_THUMBPRINT);
    DIDDocument doc = DIDDocument::fromJson(iv.didDocJson);
    if (doc.signingPublicKey.size() != 32 ||
        !DID::verifyThumbprint(iv.requesterId, doc.signingPublicKey))
        return finish(Verdict::DENY_BINDING);

    charge(Stage::INTEREST_SIG_VERIFY);
    std::string fp = CryptoEngine::toBase64Url(CryptoEngine::sha256(iv.didDocJson));
    std::string in = interestSigningInput(iv.name, iv.requesterId, iv.nonceHex,
                                          iv.lifetimeMs, iv.signingTs, iv.vcId,
                                          iv.breakGlass, fp);
    if (!CryptoEngine::ed25519Verify(doc.signingPublicKey, Bytes(in.begin(), in.end()), sig))
        return finish(Verdict::DENY_SIGNATURE);
    if (replaySeen(iv.requesterId, iv.nonceHex, iv.signingTs, now))
        return finish(Verdict::DENY_REPLAY);

    charge(Stage::VC_PARSE_VERIFY);
    VerifiableCredential vc = VerifiableCredential::fromJson(iv.vcJson);
    if (vc.issuer != issuerDid || vc.id != iv.vcId || !vc.verifySignature(issuerPk))
        return finish(Verdict::DENY_FORGED);

    charge(Stage::CLAIMS_STATUS_POLICY);
    d.subjectRole = vc.subject.role;
    d.subjectUnit = vc.subject.unit;
    d.statusIndex = vc.statusRef.statusListIndex;
    if (vc.subject.id != iv.requesterId) return finish(Verdict::DENY_BINDING);
    if (now < vc.validFrom || now > vc.validUntil) return finish(Verdict::DENY_EXPIRED);
    CredStatus st = status ? status->lookup(vc.statusRef.statusListIndex) : CredStatus::ACTIVE;
    if (st == CredStatus::REVOKED) return finish(Verdict::DENY_REVOKED);
    if (st == CredStatus::SUSPENDED) return finish(Verdict::DENY_SUSPENDED);
    SubjectAttrs subj{vc.subject.role, vc.subject.unit, vc.subject.clearance};
    d.rule = AccessPolicy::evaluate(subj, res, iv.breakGlass);

    // Store the session even on a policy deny: the credential itself is
    // valid, and later Interests for other names may be permitted.
    charge(Stage::REKEY_UNSEAL);
    PreReKey rk;
    if (!unsealReKey(sealKey, vc.subject.reEncryptionKey, rk))
        return finish(Verdict::DENY_FORGED);
    Session s;
    s.did = iv.requesterId;
    s.signingPk = doc.signingPublicKey;
    s.keyFingerprint = fp;
    s.vcId = vc.id;
    s.subject = subj;
    s.validFrom = vc.validFrom;
    s.validUntil = vc.validUntil;
    s.statusIndex = vc.statusRef.statusListIndex;
    s.rk = rk;
    storeSession(s);

    if (d.rule.empty()) return finish(Verdict::DENY_POLICY);
    d.rk = rk;
    return finish(Verdict::GRANT);
}

// ------------------------------------------------------------ cost model

CostModel &CostModel::instance() {
    static CostModel cm;
    return cm;
}

void CostModel::calibrate() {
    if (done) return;
    done = true;   // guard against re-entry from instance()
    const int N = 400;

    Ed25519KeyPair issuer = CryptoEngine::generateEd25519KeyPair();
    std::string issuerDid = DID::fromEd25519PublicKey(issuer.publicKey);
    Ed25519KeyPair holder = CryptoEngine::generateEd25519KeyPair();
    PreKeyPair owner = UmbralPRE::keygen();
    PreKeyPair holderPre = UmbralPRE::keygen();
    Bytes seal = CryptoEngine::randomBytes(32);

    DIDDocument doc;
    doc.did = DID::fromEd25519PublicKey(holder.publicKey);
    doc.controller = doc.did;
    doc.signingPublicKey = holder.publicKey;
    doc.keyAgreementPublicKey = holderPre.pk;
    doc.created = kSimEpochBase;
    std::string docJson = doc.toJson();

    PreReKey rk = UmbralPRE::rekeygen(owner.sk, holderPre.pk);
    VerifiableCredential vc;
    vc.id = issuerDid + "#vc-0001";
    vc.issuer = issuerDid;
    vc.validFrom = kSimEpochBase;
    vc.validUntil = kSimEpochBase + 86400;
    vc.subject.id = doc.did;
    vc.subject.role = "Nurse";
    vc.subject.department = "GeneralNursing";
    vc.subject.unit = "ICU";
    vc.subject.clearance = 3;
    vc.subject.organization = "did:self:hospitalX";
    vc.subject.specialty = "GeneralNursing";
    vc.subject.licenseNumber = "LIC-0000001";
    vc.subject.reEncryptionKey = EnforcementEngine::sealReKey(seal, rk);
    vc.statusRef.statusListCredential = "/hospitalX/status/v1";
    vc.statusRef.statusListIndex = 7;
    vc.statusRef.id = "/hospitalX/status/v1#7";
    vc.proof.created = vc.validFrom;
    vc.proof.verificationMethod = issuerDid + "#keys-1";
    vc.sign(issuer.privateKey);
    std::string vcJson = vc.toJson();

    std::string fp = CryptoEngine::toBase64Url(CryptoEngine::sha256(docJson));
    std::string name = "/hospitalX/ICU/patient101/Observation/vitalSigns/v3";
    std::string in = interestSigningInput(name, doc.did, "00112233445566778899aabbccddeeff",
                                          4000, kSimEpochBase, vc.id, false, fp);
    Bytes inB(in.begin(), in.end());
    Bytes sig = CryptoEngine::ed25519Sign(holder.privateKey, inB);
    StatusList sl;
    sl.set(64, CredStatus::REVOKED);
    ResourceAttrs res = ResourceAttrs::fromName(name);
    SubjectAttrs subj{"Nurse", "ICU", 3};

    Bytes kem;
    PreCapsule cap = UmbralPRE::encapsulate(owner.pk, kem);
    std::unordered_map<std::string, int> fakeSessions;
    for (int i = 0; i < 1000; i++) fakeSessions["did:self:" + std::to_string(i)] = i;
    std::unordered_set<std::string> fakeNonces;
    long nonceCtr = 0;

    volatile bool sink = false;
    costs[(int)Stage::DID_PARSE_THUMBPRINT] = timeMedian(N, [&] {
        DIDDocument d2 = DIDDocument::fromJson(docJson);
        sink = DID::verifyThumbprint(doc.did, d2.signingPublicKey);
    });
    costs[(int)Stage::INTEREST_SIG_VERIFY] = timeMedian(N, [&] {
        std::string fp2 = CryptoEngine::toBase64Url(CryptoEngine::sha256(docJson));
        sink = CryptoEngine::ed25519Verify(holder.publicKey, inB, sig) && !fp2.empty();
    });
    costs[(int)Stage::VC_PARSE_VERIFY] = timeMedian(N, [&] {
        VerifiableCredential v2 = VerifiableCredential::fromJson(vcJson);
        sink = v2.verifySignature(issuer.publicKey);
    });
    costs[(int)Stage::CLAIMS_STATUS_POLICY] = timeMedian(N, [&] {
        CredStatus st = sl.lookup(7);
        sink = !AccessPolicy::evaluate(subj, ResourceAttrs::fromName(name), false).empty() &&
               st == CredStatus::ACTIVE;
    });
    costs[(int)Stage::REKEY_UNSEAL] = timeMedian(N, [&] {
        PreReKey r2;
        sink = EnforcementEngine::unsealReKey(seal, vc.subject.reEncryptionKey, r2);
    });
    costs[(int)Stage::SESSION_LOOKUP] = timeMedian(N, [&] {
        sink = fakeSessions.count("did:self:517") > 0 &&
               fakeNonces.insert(std::to_string(nonceCtr++)).second;
    });
    costs[(int)Stage::PRE_REENCAPSULATE] = timeMedian(N, [&] {
        PreCFrag f;
        sink = UmbralPRE::reencapsulate(rk, cap, f);
    });
    Bytes decision(160, 0x5a);
    Bytes dsig = CryptoEngine::ed25519Sign(issuer.privateKey, decision);
    costs[(int)Stage::DECISION_SIGN] = timeMedian(N, [&] {
        sink = !CryptoEngine::ed25519Sign(issuer.privateKey, decision).empty();
    });
    costs[(int)Stage::DECISION_VERIFY] = timeMedian(N, [&] {
        sink = CryptoEngine::ed25519Verify(issuer.publicKey, decision, dsig);
    });
    costs[(int)Stage::POLICY_ONLY] = timeMedian(N, [&] {
        sink = !AccessPolicy::evaluate(subj, ResourceAttrs::fromName(name), false).empty() &&
               fakeSessions.count("did:self:517") > 0;
    });
    sign = timeMedian(N, [&] { sink = !CryptoEngine::ed25519Sign(holder.privateKey, inB).empty(); });
    verify = costs[(int)Stage::DECISION_VERIFY];
    Bytes plain(4096, 0x41), dek = CryptoEngine::randomBytes(32), aad(name.begin(), name.end());
    aesKiB = timeMedian(N, [&] { sink = !CryptoEngine::aesGcmEncrypt(dek, plain, aad).ciphertext.empty(); }) / 4.0;
    encap = timeMedian(N, [&] { Bytes k; sink = !UmbralPRE::encapsulate(owner.pk, k).s.empty(); });
    PreCFrag frag;
    UmbralPRE::reencapsulate(rk, cap, frag);
    decap = timeMedian(N, [&] { Bytes k; sink = UmbralPRE::decapsulateFrag(holderPre.sk, cap, frag, k); });
    (void)sink;
}

void CostModel::loadOrCalibrate(const std::string &path) {
    FILE *f = path.empty() ? nullptr : std::fopen(path.c_str(), "r");
    if (f) {
        double v[(int)Stage::COUNT + 5];
        int n = 0;
        while (n < (int)Stage::COUNT + 5 && std::fscanf(f, "%lf", &v[n]) == 1) n++;
        std::fclose(f);
        if (n == (int)Stage::COUNT + 5) {
            for (int i = 0; i < (int)Stage::COUNT; i++) costs[i] = v[i];
            sign = v[(int)Stage::COUNT];
            verify = v[(int)Stage::COUNT + 1];
            aesKiB = v[(int)Stage::COUNT + 2];
            encap = v[(int)Stage::COUNT + 3];
            decap = v[(int)Stage::COUNT + 4];
            done = true;
            return;
        }
    }
    done = false;
    calibrate();
    if (path.empty()) return;
    f = std::fopen(path.c_str(), "w");
    if (!f) return;
    for (int i = 0; i < (int)Stage::COUNT; i++) std::fprintf(f, "%.9e\n", costs[i]);
    std::fprintf(f, "%.9e\n%.9e\n%.9e\n%.9e\n%.9e\n", sign, verify, aesKiB, encap, decap);
    std::fclose(f);
}

std::string CostModel::report() const {
    std::ostringstream o;
    o << "stage,median_us\n";
    for (int i = 0; i < (int)Stage::COUNT; i++)
        o << stageName((Stage)i) << "," << costs[i] * 1e6 << "\n";
    o << "ed25519_sign," << sign * 1e6 << "\n";
    o << "aes_gcm_per_kib," << aesKiB * 1e6 << "\n";
    o << "pre_encapsulate," << encap * 1e6 << "\n";
    o << "pre_decapsulate," << decap * 1e6 << "\n";
    return o.str();
}

} // namespace ndnpreencryption
