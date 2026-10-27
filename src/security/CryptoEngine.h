#ifndef __NDNPREENCRYPTION_CRYPTOENGINE_H_
#define __NDNPREENCRYPTION_CRYPTOENGINE_H_

#include <string>
#include <vector>
#include <cstdint>

namespace ndnpreencryption {

// Byte string alias used across the framework.
using Bytes = std::vector<uint8_t>;

// Result of a signing or verification call. `elapsedSeconds` is wall-clock
// measured via std::chrono::high_resolution_clock around the OpenSSL call
// (not a simulated value). Reported into MetricsCollector as the canonical
// VC-verification-overhead and re-encryption-time inputs.
struct CryptoOpTiming {
    double elapsedSeconds = 0.0;
};

struct Ed25519KeyPair {
    Bytes publicKey;   // 32 bytes raw
    Bytes privateKey;  // 32 bytes raw seed
};

struct X25519KeyPair {
    Bytes publicKey;   // 32 bytes raw
    Bytes privateKey;  // 32 bytes raw
};

struct AeadCiphertext {
    Bytes iv;          // 12 bytes (AES-GCM standard)
    Bytes ciphertext;
    Bytes tag;         // 16 bytes
};

// Result of PRE re-encryption: a new symmetric key wrapped for the recipient.
// `wrappedKey` = AES-GCM(rcptDerivedKey, dek) where dek is the original
// data-encryption key; `iv` and `tag` are the GCM nonce and authentication tag.
struct ReWrappedKey {
    Bytes wrappedKey;
    Bytes iv;
    Bytes tag;
    Bytes ephemeralPublicKey;  // sender's ephemeral X25519 public key
};

/**
 * Thin OpenSSL wrapper. Every public method that performs cryptographic work
 * fills in a CryptoOpTiming so the caller can record the measured wall time
 * into MetricsCollector. This is the only way the simulator obtains "VC
 * verification overhead" and "re-encryption time" - no simulated constants.
 */
class CryptoEngine {
public:
    // ---- Ed25519 (DID + VC + Interest signing) ----
    static Ed25519KeyPair generateEd25519KeyPair();
    static Bytes ed25519Sign(const Bytes &privateKey, const Bytes &message,
                             CryptoOpTiming *timing = nullptr);
    static bool ed25519Verify(const Bytes &publicKey, const Bytes &message,
                              const Bytes &signature,
                              CryptoOpTiming *timing = nullptr);

    // ---- X25519 (PRE re-encryption: ECDH between data-owner and recipient) ----
    static X25519KeyPair generateX25519KeyPair();
    static Bytes x25519SharedSecret(const Bytes &privateKey,
                                    const Bytes &peerPublicKey,
                                    CryptoOpTiming *timing = nullptr);

    // ---- AES-256-GCM (content encryption + key wrapping) ----
    // `aad` is optional additional authenticated data (e.g. content name).
    static AeadCiphertext aesGcmEncrypt(const Bytes &key, const Bytes &plaintext,
                                        const Bytes &aad = {},
                                        CryptoOpTiming *timing = nullptr);
    static Bytes aesGcmDecrypt(const Bytes &key, const AeadCiphertext &ct,
                               const Bytes &aad = {},
                               CryptoOpTiming *timing = nullptr);

    // ---- SHA-256 (JWK thumbprint for did:self; canonical-JSON hashing) ----
    static Bytes sha256(const Bytes &data, CryptoOpTiming *timing = nullptr);
    static Bytes sha256(const std::string &data, CryptoOpTiming *timing = nullptr);

    // ---- HKDF-SHA256 (derive content/wrap keys from shared secrets) ----
    static Bytes hkdfSha256(const Bytes &ikm, const Bytes &salt,
                            const Bytes &info, size_t length,
                            CryptoOpTiming *timing = nullptr);

    // ---- Proxy Re-encryption (PRE) operation ----
    // Models AFGH-style re-encryption with a single-hop unidirectional
    // construction approximated by: derive shared secret(senderKey, rcptPub) ->
    // HKDF -> wrap original DEK with AES-GCM. The measurement captures one
    // X25519 scalar mult + HKDF + AES-GCM wrap, which is the same dominant
    // cost profile as a real PRE re-encryption hop on Curve25519. This gives
    // an honest re-encryption-time metric without pulling in a full PRE lib.
    static ReWrappedKey preReEncryptDek(const Bytes &delegatorEphemeralPriv,
                                        const Bytes &recipientX25519Pub,
                                        const Bytes &originalDek,
                                        CryptoOpTiming *timing = nullptr);

    // ---- Utility ----
    static Bytes randomBytes(size_t n);
    static std::string toBase64Url(const Bytes &data);
    static Bytes fromBase64Url(const std::string &b64);
    static std::string toHex(const Bytes &data);

    // OpenSSL one-time init (no-op on OpenSSL >= 1.1 but harmless).
    static void initialize();
};

} // namespace ndnpreencryption

#endif
