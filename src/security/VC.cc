#include "VC.h"
#include "DID.h"
#include "../utils/Json.h"

#include <sstream>

namespace ndnpreencryption {

namespace {
// PPTX uses string clearance levels (level1..level5). When the caller leaves
// `clearanceLevel` empty we derive it from the numeric `clearance` so old
// configs keep working without code changes elsewhere.
std::string defaultLevelString(int clearance) {
    if (clearance < 1) clearance = 1;
    if (clearance > 5) clearance = 5;
    return std::string("level") + std::to_string(clearance);
}

std::string subjectObject(const CredentialSubject &s, uint32_t mask) {
    Json::ObjectBuilder b;
    b.addString("id", s.id);
    if (mask & VC_ATTR_ROLE)         b.addString("role", s.role);
    if (mask & VC_ATTR_DEPARTMENT)   b.addString("department",
                                         s.department.empty() ? s.unit : s.department);
    if (mask & VC_ATTR_UNIT)         b.addString("unit", s.unit);
    if (mask & VC_ATTR_CLEARANCE) {
        b.addInt("clearance", s.clearance);
        b.addString("clearanceLevel",
                    s.clearanceLevel.empty() ? defaultLevelString(s.clearance)
                                              : s.clearanceLevel);
    }
    if (mask & VC_ATTR_ORGANIZATION) b.addString("organization", s.organization);
    if (mask & VC_ATTR_SPECIALTY)    b.addString("specialty", s.specialty);
    if (mask & VC_ATTR_LICENSE_NO)   b.addString("licenseNumber", s.licenseNumber);
    if (!s.reEncryptionKey.empty())  b.addString("reEncryptionKey", s.reEncryptionKey);
    return b.str();
}

std::string statusObject(const CredentialStatusRef &r) {
    Json::ObjectBuilder b;
    b.addString("id", r.id)
     .addString("type", r.type)
     .addInt("statusListIndex", r.statusListIndex)
     .addString("statusListCredential", r.statusListCredential)
     .addString("statusPurpose", r.statusPurpose);
    return b.str();
}

std::string proofObject(const VcProof &p, bool withSignature) {
    Json::ObjectBuilder b;
    b.addString("type", p.type)
     .addString("created", toIso8601Utc(p.created))
     .addString("verificationMethod", p.verificationMethod)
     .addString("proofPurpose", p.proofPurpose);
    if (withSignature) {
        b.addString("proofValue", CryptoEngine::toBase64Url(p.signatureBytes));
    }
    return b.str();
}
} // namespace

std::string VerifiableCredential::toJson() const {
    Json::ObjectBuilder b;
    b.addRawString("@context",
                   "[\"https://www.w3.org/ns/credentials/v2\","
                   "\"https://w3id.org/healthcare-vocab/v1\"]")
     .addString("id", id)
     .addArrayOfStrings("type", types)
     .addString("issuer", issuer)
     .addString("validFrom", toIso8601Utc(validFrom))
     .addString("validUntil", toIso8601Utc(validUntil))
     .addRaw("credentialSubject", subjectObject(subject, disclosureMask))
     .addRaw("credentialStatus", statusObject(statusRef))
     .addRaw("proof", proofObject(proof, true));
    return b.str();
}

std::string VerifiableCredential::toCanonicalSigningBytes() const {
    Json::ObjectBuilder b;
    b.addRawString("@context",
                   "[\"https://www.w3.org/ns/credentials/v2\","
                   "\"https://w3id.org/healthcare-vocab/v1\"]")
     .addString("id", id)
     .addArrayOfStrings("type", types)
     .addString("issuer", issuer)
     .addString("validFrom", toIso8601Utc(validFrom))
     .addString("validUntil", toIso8601Utc(validUntil))
     // Always sign over the FULL subject — disclosure is a presentation-time
     // concern, not an issuance-time one.
     .addRaw("credentialSubject", subjectObject(subject, VC_ATTR_ALL))
     .addRaw("credentialStatus", statusObject(statusRef))
     // Proof without the signature value (the "to-be-signed" canonical form
     // per the W3C Data Integrity spec).
     .addRaw("proof", proofObject(proof, false));
    return b.str();
}

std::string VerifiableCredential::toJsonWithDisclosure(uint32_t mask) const {
    VerifiableCredential redacted = *this;
    redacted.disclosureMask = mask;
    return redacted.toJson();
}

VerifiableCredential VerifiableCredential::fromJson(const std::string &json) {
    VerifiableCredential v;
    v.id     = Json::extractString(json, "id");
    v.issuer = Json::extractString(json, "issuer");

    // Dates: prefer ISO 8601 string, fall back to int epoch for older payloads.
    {
        std::string s = Json::extractString(json, "validFrom");
        v.validFrom = s.empty() ? Json::extractInt(json, "validFrom")
                                : fromIso8601Utc(s);
    }
    {
        std::string s = Json::extractString(json, "validUntil");
        v.validUntil = s.empty() ? Json::extractInt(json, "validUntil")
                                 : fromIso8601Utc(s);
    }

    std::string subj = Json::extractObject(json, "credentialSubject");
    if (!subj.empty()) {
        v.subject.id             = Json::extractString(subj, "id");
        v.subject.role           = Json::extractString(subj, "role");
        v.subject.department     = Json::extractString(subj, "department");
        v.subject.unit           = Json::extractString(subj, "unit");
        v.subject.clearance      = static_cast<int>(Json::extractInt(subj, "clearance", 1));
        v.subject.clearanceLevel = Json::extractString(subj, "clearanceLevel");
        v.subject.organization   = Json::extractString(subj, "organization");
        v.subject.specialty      = Json::extractString(subj, "specialty");
        v.subject.licenseNumber  = Json::extractString(subj, "licenseNumber");
        v.subject.reEncryptionKey = Json::extractString(subj, "reEncryptionKey");
    }

    std::string st = Json::extractObject(json, "credentialStatus");
    if (!st.empty()) {
        v.statusRef.id                   = Json::extractString(st, "id");
        v.statusRef.type                 = Json::extractString(st, "type");
        v.statusRef.statusListIndex      = static_cast<int>(Json::extractInt(st, "statusListIndex"));
        v.statusRef.statusListCredential = Json::extractString(st, "statusListCredential");
        v.statusRef.statusPurpose        = Json::extractString(st, "statusPurpose");
    }

    std::string pr = Json::extractObject(json, "proof");
    if (!pr.empty()) {
        v.proof.type               = Json::extractString(pr, "type");
        std::string c              = Json::extractString(pr, "created");
        v.proof.created            = c.empty() ? Json::extractInt(pr, "created")
                                                : fromIso8601Utc(c);
        v.proof.verificationMethod = Json::extractString(pr, "verificationMethod");
        v.proof.proofPurpose       = Json::extractString(pr, "proofPurpose");
        std::string sig            = Json::extractString(pr, "proofValue");
        v.proof.signatureBytes     = CryptoEngine::fromBase64Url(sig);
    }
    return v;
}

void VerifiableCredential::sign(const Bytes &issuerPrivateKey,
                                CryptoOpTiming *timing) {
    std::string canon = toCanonicalSigningBytes();
    Bytes msg(canon.begin(), canon.end());
    proof.signatureBytes = CryptoEngine::ed25519Sign(issuerPrivateKey, msg, timing);
}

bool VerifiableCredential::verifySignature(const Bytes &issuerPublicKey,
                                           CryptoOpTiming *timing) const {
    std::string canon = toCanonicalSigningBytes();
    Bytes msg(canon.begin(), canon.end());
    return CryptoEngine::ed25519Verify(issuerPublicKey, msg,
                                       proof.signatureBytes, timing);
}

} // namespace ndnpreencryption
