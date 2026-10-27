#ifndef __NDNPREENCRYPTION_DID_H_
#define __NDNPREENCRYPTION_DID_H_

#include <string>
#include "CryptoEngine.h"

namespace ndnpreencryption {

// ISO 8601 UTC date helpers shared across VC / VCList / DIDDocument so the
// on-wire JSON matches the PPTX literal date format.
std::string toIso8601Utc(long long epochSeconds);
// Simulated time 0 maps to 2026-10-01T00:00:00Z so serialized dates read as
// real calendar dates.
constexpr long long kSimEpochBase = 1790812800LL;
long long   fromIso8601Utc(const std::string &iso);

/**
 * did:self method (registry-free DID) implementation.
 *
 * Per the excid-io/did-self specification and RFC 7638, the DID is the
 * base64url-encoded SHA-256 thumbprint of a canonical JWK representing the
 * controller's signing public key.
 *
 *   did = "did:self:" + base64url( SHA-256( canonicalJwk(Ed25519 publicKey) ) )
 *
 * The DID Document carries the same public key as a verificationMethod with
 * type "Ed25519VerificationKey2020" and publicKeyMultibase encoding (base58
 * prefix 'z' per W3C did-core). For simulation realism we substitute
 * base64url for multibase — the verifier doesn't care which encoding is used,
 * only that the bytes match the thumbprint after decoding.
 */
class DID {
public:
    // Canonical JWK string for an Ed25519 public key, per RFC 8037 (OKP),
    // with members sorted as required by RFC 7638:
    //   {"crv":"Ed25519","kty":"OKP","x":"<base64url(pub)>"}
    static std::string canonicalJwkEd25519(const Bytes &publicKey);

    // Canonical EC JWK (crv=P-256) for the proxy re-encryption public key.
    static std::string canonicalJwkP256(const Bytes &compressedPoint);

    // Compute did:self identifier from an Ed25519 public key (32 bytes).
    static std::string fromEd25519PublicKey(const Bytes &publicKey,
                                            CryptoOpTiming *timing = nullptr);

    // Verify that a candidate did:self identifier matches a given public key
    // (i.e. recompute the thumbprint and compare). Reports the timing of the
    // SHA-256 + b64 operations.
    static bool verifyThumbprint(const std::string &did,
                                 const Bytes &publicKey,
                                 CryptoOpTiming *timing = nullptr);
};

/**
 * DID Document — minimal but conformant to W3C did-core core schema.
 * Carries the verificationMethod used to verify Interests signed by the
 * controller. In our embedding the Consumer ships this inside every Interest
 * so the verifier needs no registry lookup.
 */
struct DIDDocument {
    std::string did;                  // "did:self:<thumbprint>"
    Bytes signingPublicKey;           // Ed25519, 32 bytes
    Bytes keyAgreementPublicKey;      // P-256 compressed point, PRE delegatee key
    long long created = 0;            // unix epoch seconds
    std::string controller;           // usually = did (self-controlled)

    // Render as canonical JSON suitable for embedding inside an Interest.
    std::string toJson() const;
    static DIDDocument fromJson(const std::string &json);

    // Total serialised size in bytes (the verifier uses this directly to set
    // packet byteLength rather than guessing).
    size_t serializedSize() const { return toJson().size(); }
};

} // namespace ndnpreencryption

#endif
