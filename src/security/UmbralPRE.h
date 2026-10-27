#ifndef __NDNPREENCRYPTION_UMBRALPRE_H_
#define __NDNPREENCRYPTION_UMBRALPRE_H_

#include "CryptoEngine.h"

namespace ndnpreencryption {

/**
 * Unidirectional, single-hop proxy re-encryption in the KEM style of Umbral
 * (Nunez, Agudo and Lopez, 2017), non-threshold case (t = n = 1), on NIST
 * P-256 with OpenSSL's EC arithmetic. Additive notation, generator G,
 * group order q.
 *
 *   Encapsulate(A):   r,u <- Z_q;  E = rG, V = uG, h = H2(E,V), s = u + r h
 *                     K = KDF((r+u) A);  capsule = (E, V, s)
 *   Check(capsule):   sG == V + hE
 *   ReKeyGen(a, B):   x <- Z_q, X = xG, d = H3(X, B, xB), rk = a d^-1
 *   ReEncapsulate:    Check(capsule); E' = rk E, V' = rk V; cfrag = (E',V',X)
 *   DecapFrag(b):     d = H3(X, B, bX);  K = KDF(d (E' + V'))
 *
 * Correctness: d (E'+V') = a (E+V) = (r+u) A.  The proxy holding rk learns
 * neither K nor a, and the delegatee needs b to recompute d.  Known limit of
 * every pairing-free single-hop scheme of this kind: a proxy that colludes
 * with the delegatee recovers a = rk d.
 */
struct PreKeyPair {
    Bytes sk;  // 32-byte scalar
    Bytes pk;  // 33-byte compressed point
};

struct PreCapsule {
    Bytes E, V;  // compressed points
    Bytes s;     // 32-byte scalar
    size_t wireSize() const { return E.size() + V.size() + s.size(); }
};

struct PreReKey {
    Bytes rk;    // 32-byte scalar
    Bytes X;     // compressed point (precursor)
    Bytes serialize() const;
    static PreReKey deserialize(const Bytes &b);
};

struct PreCFrag {
    Bytes E1, V1, X;
    size_t wireSize() const { return E1.size() + V1.size() + X.size(); }
};

class UmbralPRE {
  public:
    static PreKeyPair keygen();
    static PreCapsule encapsulate(const Bytes &pkA, Bytes &keyOut,
                                  CryptoOpTiming *t = nullptr);
    static bool checkCapsule(const PreCapsule &c);
    static bool decapsulateOriginal(const Bytes &skA, const PreCapsule &c,
                                    Bytes &keyOut);
    static PreReKey rekeygen(const Bytes &skA, const Bytes &pkB,
                             CryptoOpTiming *t = nullptr);
    static bool reencapsulate(const PreReKey &rk, const PreCapsule &c,
                              PreCFrag &out, CryptoOpTiming *t = nullptr);
    static bool decapsulateFrag(const Bytes &skB, const PreCapsule &c,
                                const PreCFrag &f, Bytes &keyOut,
                                CryptoOpTiming *t = nullptr);

    // JWK helpers for DID documents (EC P-256: x, y affine coordinates).
    static bool pointToXY(const Bytes &compressed, Bytes &x, Bytes &y);
    static Bytes pointFromXY(const Bytes &x, const Bytes &y);
};

} // namespace ndnpreencryption

#endif
