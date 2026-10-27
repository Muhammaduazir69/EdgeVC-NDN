#include "StatusList.h"
#include "../utils/Json.h"

namespace ndnpreencryption {

const char *credStatusName(CredStatus s) {
    switch (s) {
        case CredStatus::ACTIVE: return "active";
        case CredStatus::REVOKED: return "revoked";
        case CredStatus::SUSPENDED: return "suspended";
    }
    return "unknown";
}

std::string StatusDelta::signingInput() const {
    Json::ObjectBuilder b;
    b.addString("type", "BitstringStatusListDelta")
     .addString("issuer", issuerDid)
     .addInt("baseVersion", baseVersion)
     .addInt("newVersion", newVersion)
     .addInt("statusListIndex", index)
     .addInt("status", (int)status)
     .addInt("issuedAt", issuedAt);
    return b.str();
}

std::string StatusDelta::toJson() const {
    std::string body = signingInput();
    body.pop_back();
    return body + ",\"proofValue\":\"" + CryptoEngine::toBase64Url(signature) + "\"}";
}

StatusDelta StatusDelta::fromJson(const std::string &j) {
    StatusDelta d;
    d.issuerDid = Json::extractString(j, "issuer");
    d.baseVersion = (int)Json::extractInt(j, "baseVersion");
    d.newVersion = (int)Json::extractInt(j, "newVersion");
    d.index = (int)Json::extractInt(j, "statusListIndex", -1);
    d.status = (CredStatus)Json::extractInt(j, "status");
    d.issuedAt = Json::extractInt(j, "issuedAt");
    d.signature = CryptoEngine::fromBase64Url(Json::extractString(j, "proofValue"));
    return d;
}

void StatusDelta::sign(const Bytes &sk) {
    std::string in = signingInput();
    signature = CryptoEngine::ed25519Sign(sk, Bytes(in.begin(), in.end()));
}

bool StatusDelta::verify(const Bytes &pk, CryptoOpTiming *t) const {
    std::string in = signingInput();
    return CryptoEngine::ed25519Verify(pk, Bytes(in.begin(), in.end()), signature, t);
}

std::string StatusSnapshot::signingInput() const {
    Json::ObjectBuilder b;
    b.addString("type", "BitstringStatusListCredential")
     .addString("issuer", issuerDid)
     .addString("id", listName)
     .addInt("version", version)
     .addInt("statusSize", 2)
     .addInt("size", size)
     .addInt("issuedAt", issuedAt)
     .addString("encodedList", encodedList);
    return b.str();
}

std::string StatusSnapshot::toJson() const {
    std::string body = signingInput();
    body.pop_back();
    return body + ",\"proofValue\":\"" + CryptoEngine::toBase64Url(signature) + "\"}";
}

StatusSnapshot StatusSnapshot::fromJson(const std::string &j) {
    StatusSnapshot s;
    s.issuerDid = Json::extractString(j, "issuer");
    s.listName = Json::extractString(j, "id");
    s.version = (int)Json::extractInt(j, "version");
    s.size = (int)Json::extractInt(j, "size");
    s.issuedAt = Json::extractInt(j, "issuedAt");
    s.encodedList = Json::extractString(j, "encodedList");
    s.signature = CryptoEngine::fromBase64Url(Json::extractString(j, "proofValue"));
    return s;
}

void StatusSnapshot::sign(const Bytes &sk) {
    std::string in = signingInput();
    signature = CryptoEngine::ed25519Sign(sk, Bytes(in.begin(), in.end()));
}

bool StatusSnapshot::verify(const Bytes &pk, CryptoOpTiming *t) const {
    std::string in = signingInput();
    return CryptoEngine::ed25519Verify(pk, Bytes(in.begin(), in.end()), signature, t);
}

CredStatus StatusList::lookup(int index) const {
    if (index < 0 || index >= (int)statuses.size()) return CredStatus::ACTIVE;
    return (CredStatus)statuses[index];
}

void StatusList::set(int index, CredStatus s) {
    if (index < 0) return;
    if (index >= (int)statuses.size()) statuses.resize(index + 1, 0);
    statuses[index] = (uint8_t)s;
}

StatusList::ApplyResult StatusList::applyDelta(const StatusDelta &d, const Bytes &pk,
                                               CryptoOpTiming *t) {
    if (!d.verify(pk, t)) return ApplyResult::BAD_SIGNATURE;
    if (d.newVersion <= currentVersion) return ApplyResult::STALE;
    if (d.newVersion > currentVersion + 1) return ApplyResult::GAP;
    set(d.index, d.status);
    currentVersion = d.newVersion;
    return ApplyResult::APPLIED;
}

StatusList::ApplyResult StatusList::applySnapshot(const StatusSnapshot &s, const Bytes &pk,
                                                  CryptoOpTiming *t) {
    if (!s.verify(pk, t)) return ApplyResult::BAD_SIGNATURE;
    if (s.version <= currentVersion) return ApplyResult::STALE;
    Bytes packed = CryptoEngine::fromBase64Url(s.encodedList);
    statuses.assign(s.size, 0);
    for (int i = 0; i < s.size; i++) {
        int byte = i / 4, shift = (i % 4) * 2;
        if (byte < (int)packed.size()) statuses[i] = (packed[byte] >> shift) & 0x3;
    }
    currentVersion = s.version;
    return ApplyResult::APPLIED;
}

StatusSnapshot StatusList::buildSnapshot(const std::string &issuerDid,
                                         const std::string &listName,
                                         long long issuedAt) const {
    StatusSnapshot s;
    s.issuerDid = issuerDid;
    s.listName = listName;
    s.version = currentVersion;
    s.size = (int)statuses.size();
    s.issuedAt = issuedAt;
    Bytes packed((statuses.size() + 3) / 4, 0);
    for (size_t i = 0; i < statuses.size(); i++)
        packed[i / 4] |= (uint8_t)((statuses[i] & 0x3) << ((i % 4) * 2));
    s.encodedList = CryptoEngine::toBase64Url(packed);
    return s;
}

} // namespace ndnpreencryption
