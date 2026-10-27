#ifndef __NDNPREENCRYPTION_VC_H_
#define __NDNPREENCRYPTION_VC_H_

#include <string>
#include <vector>
#include <cstdint>
#include "CryptoEngine.h"

namespace ndnpreencryption {

// Selective disclosure mask. Each bit gates one attribute of the
// credentialSubject when the consumer presents the VC inside an Interest.
enum VcAttribute : uint32_t {
    VC_ATTR_ROLE         = 1u << 0,
    VC_ATTR_UNIT         = 1u << 1,
    VC_ATTR_CLEARANCE    = 1u << 2,
    VC_ATTR_ORGANIZATION = 1u << 3,
    VC_ATTR_SPECIALTY    = 1u << 4,
    VC_ATTR_LICENSE_NO   = 1u << 5,
    VC_ATTR_DEPARTMENT   = 1u << 6,
    VC_ATTR_ALL          = 0xFFFFFFFFu,
};

/**
 * Credential subject attributes for healthcare clinicians. Mirrors typical
 * HL7 FHIR Practitioner / PractitionerRole fields.
 */
struct CredentialSubject {
    std::string id;            // holder DID
    std::string role;          // Physician, Nurse, RadiologyTech, ...
    std::string department;    // PPTX: top-level department (e.g. "Cardiology")
    std::string unit;          // ICU, Emergency, ClinicA, Pediatrics
    int         clearance = 1; // 1..5, higher = more privileged
    std::string clearanceLevel;// PPTX: string form (e.g. "level3"); derived
                               // from `clearance` if left empty on serialise.
    std::string organization;  // "did:self:hospitalX"
    std::string specialty;     // e.g. "Cardiology"
    std::string licenseNumber;
    // Re-encryption key rk(owner -> holder) sealed under the infrastructure
    // key of the enforcement points (AES-256-GCM, base64url). The holder
    // cannot open it; an edge router can, and needs it to re-encapsulate.
    std::string reEncryptionKey;
};

/**
 * VC status reference per W3C Bitstring Status List v1.0.
 * statusListCredential is an NDN content name that resolves to a VCList
 * snapshot; statusListIndex picks this credential's slot in the bitstring.
 */
struct CredentialStatusRef {
    std::string id;                       // "<statusListCredential>#<index>"
    std::string type = "BitstringStatusListEntry";
    int         statusListIndex = 0;
    std::string statusListCredential;     // NDN name of the VCList content
    std::string statusPurpose = "revocation";
};

/**
 * Proof block. Renders as the W3C `Ed25519Signature2020` suite to match the
 * PPTX spec literally. `created` serialises as ISO 8601 UTC.
 */
struct VcProof {
    std::string type = "Ed25519Signature2020";
    long long   created = 0;
    std::string verificationMethod;   // "<issuerDID>#keys-1"
    std::string proofPurpose = "assertionMethod";
    Bytes       signatureBytes;       // raw Ed25519 signature (64 bytes)
};

/**
 * W3C VC 2.0 Verifiable Credential, restricted to the fields we need for
 * NDN access control. `id` is a URN; issuer is a DID; validFrom/Until are
 * RFC 3339 epoch-seconds (we store seconds and emit as integers to keep
 * canonicalisation trivial — a real verifier would emit ISO 8601 strings,
 * but this changes only the byte size of the JSON, not the security model).
 */
struct VerifiableCredential {
    // PPTX format: `<issuerDID>#vc-NNNN`. Issuer assigns a monotonic ordinal.
    std::string id;
    std::vector<std::string> types{"VerifiableCredential", "MedicalStaffCredential"};
    std::string issuer;                        // issuer DID
    long long   validFrom = 0;                 // epoch seconds (serialised as ISO 8601)
    long long   validUntil = 0;                // epoch seconds (serialised as ISO 8601)
    CredentialSubject subject;
    CredentialStatusRef statusRef;
    VcProof proof;

    // Selective disclosure mask: which fields of `subject` to reveal when
    // serializing for transport. Defaults to all.
    uint32_t disclosureMask = VC_ATTR_ALL;

    // Canonical JSON serialisation *with* proof block (full credential).
    std::string toJson() const;

    // Canonical JSON serialisation *without* the proof.signatureBytes field
    // (everything else preserved). This is the byte string the issuer signs
    // and the verifier re-canonicalises before calling Ed25519 verify.
    std::string toCanonicalSigningBytes() const;

    // Parse from JSON. Recovers all structured fields; signature bytes are
    // base64url-decoded back from proof.proofValue.
    static VerifiableCredential fromJson(const std::string &json);

    // Issuer-side helper: compute proof.signatureBytes by Ed25519-signing the
    // canonical bytes with `issuerPrivateKey`.
    void sign(const Bytes &issuerPrivateKey, CryptoOpTiming *timing = nullptr);

    // Verifier-side helper.
    bool verifySignature(const Bytes &issuerPublicKey,
                         CryptoOpTiming *timing = nullptr) const;

    // Convenience: serialised size (drives Interest byteLength). Honours
    // the disclosure mask.
    size_t serializedSize() const { return toJson().size(); }

    // Selective-disclosure-aware serialisation: drops masked subject fields
    // but keeps the proof intact (the signature still verifies against the
    // canonical full-credential bytes only if disclosureMask == ALL; for
    // partial disclosure the verifier must re-verify against the redacted
    // claims using a different proof mechanism — out of scope for the
    // baseline scenarios but available for the compromise / privacy
    // scenario).
    std::string toJsonWithDisclosure(uint32_t mask) const;
};

} // namespace ndnpreencryption

#endif
