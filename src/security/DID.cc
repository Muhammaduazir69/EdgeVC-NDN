#include "DID.h"
#include "../utils/Json.h"
#include "UmbralPRE.h"

#include <ctime>
#include <cstring>

namespace ndnpreencryption {

std::string DID::canonicalJwkEd25519(const Bytes &publicKey) {
    // RFC 7638 §3: only the required members, in lexicographic order, with
    // no whitespace. For OKP/Ed25519 the required members are crv, kty, x.
    return std::string("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"")
         + CryptoEngine::toBase64Url(publicKey) + "\"}";
}

std::string DID::canonicalJwkP256(const Bytes &compressedPoint) {
    // RFC 7518 EC JWK; required members crv, kty, x, y in lexicographic order.
    Bytes x, y;
    UmbralPRE::pointToXY(compressedPoint, x, y);
    return std::string("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"")
         + CryptoEngine::toBase64Url(x) + "\",\"y\":\""
         + CryptoEngine::toBase64Url(y) + "\"}";
}

std::string DID::fromEd25519PublicKey(const Bytes &publicKey,
                                      CryptoOpTiming *timing) {
    std::string jwk = canonicalJwkEd25519(publicKey);
    Bytes hash = CryptoEngine::sha256(jwk, timing);
    return "did:self:" + CryptoEngine::toBase64Url(hash);
}

bool DID::verifyThumbprint(const std::string &did,
                           const Bytes &publicKey,
                           CryptoOpTiming *timing) {
    std::string expected = fromEd25519PublicKey(publicKey, timing);
    return expected == did;
}

// ISO 8601 (UTC, no fractional seconds) — used in DID Documents, VCs, VCList
// entries, and proofs so the on-wire JSON matches the PPTX spec exactly.
std::string toIso8601Utc(long long epochSeconds) {
    if (epochSeconds <= 0) return "1970-01-01T00:00:00Z";
    time_t t = (time_t)epochSeconds;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

long long fromIso8601Utc(const std::string &s) {
    if (s.empty()) return 0;
    struct tm tmv = {};
    if (strptime(s.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tmv) == nullptr)
        return 0;
    return (long long)timegm(&tmv);
}

std::string DIDDocument::toJson() const {
    // verificationMethod array: JsonWebKey2020 entries embed the raw key
    // material in publicKeyJwk (RFC 7517/8037 OKP). One Ed25519 signing key,
    // one P-256 key used as the proxy re-encryption delegatee key.
    Json::ObjectBuilder signMethod;
    signMethod.addString("id", did + "#keys-1")
              .addString("type", "JsonWebKey2020")
              .addString("controller", controller.empty() ? did : controller)
              .addRaw("publicKeyJwk", DID::canonicalJwkEd25519(signingPublicKey));

    Json::ObjectBuilder kaMethod;
    kaMethod.addString("id", did + "#keys-2")
            .addString("type", "JsonWebKey2020")
            .addString("controller", controller.empty() ? did : controller)
            .addRaw("publicKeyJwk", DID::canonicalJwkP256(keyAgreementPublicKey));

    std::string vmArray = "[" + signMethod.str() + "," + kaMethod.str() + "]";

    Json::ObjectBuilder doc;
    doc.addRawString("@context",
                     "[\"https://www.w3.org/ns/did/v1\","
                     "\"https://w3id.org/security/suites/jws-2020/v1\"]")
       .addString("id", did)
       .addString("controller", controller.empty() ? did : controller)
       .addString("created", toIso8601Utc(created))
       .addRaw("verificationMethod", vmArray)
       .addArrayOfStrings("authentication", {did + "#keys-1"})
       .addArrayOfStrings("keyAgreement", {did + "#keys-2"});
    return doc.str();
}

DIDDocument DIDDocument::fromJson(const std::string &json) {
    DIDDocument d;
    d.did = Json::extractString(json, "id");
    d.controller = Json::extractString(json, "controller");
    if (d.controller.empty()) d.controller = d.did;
    // `created` is stored as ISO 8601 in the current schema. Older serialised
    // documents may still carry an integer; tolerate both.
    std::string createdIso = Json::extractString(json, "created");
    if (!createdIso.empty()) d.created = fromIso8601Utc(createdIso);
    else                     d.created = Json::extractInt(json, "created");

    // Iterate the verificationMethod array and pull the two public keys. The
    // current schema uses JsonWebKey2020 with publicKeyJwk; we also accept
    // the older Ed25519VerificationKey2020 + publicKeyMultibase form for any
    // residual serialised documents that may still flow during a hot upgrade.
    std::string vm = Json::extractArray(json, "verificationMethod");
    for (const auto &elem : Json::splitArrayElements(vm)) {
        std::string type = Json::extractString(elem, "type");
        Bytes raw;

        // Preferred: publicKeyJwk.x (base64url).
        std::string jwk = Json::extractObject(elem, "publicKeyJwk");
        if (!jwk.empty()) {
            std::string x = Json::extractString(jwk, "x");
            std::string crv = Json::extractString(jwk, "crv");
            if (!x.empty()) raw = CryptoEngine::fromBase64Url(x);
            if (type == "JsonWebKey2020") {
                if (crv == "Ed25519") d.signingPublicKey = raw;
                else if (crv == "P-256")
                    d.keyAgreementPublicKey = UmbralPRE::pointFromXY(
                        raw, CryptoEngine::fromBase64Url(Json::extractString(jwk, "y")));
                continue;
            }
        }
        // Fallback: legacy multibase form.
        if (raw.empty()) {
            std::string pk = Json::extractString(elem, "publicKeyMultibase");
            if (!pk.empty() && pk[0] == 'u') pk = pk.substr(1);
            raw = CryptoEngine::fromBase64Url(pk);
        }
        if (type == "Ed25519VerificationKey2020") d.signingPublicKey = raw;
        else if (type == "X25519KeyAgreementKey2020") d.keyAgreementPublicKey = raw;
    }
    return d;
}

} // namespace ndnpreencryption
