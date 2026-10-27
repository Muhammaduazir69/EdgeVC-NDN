#include "UmbralPRE.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

namespace ndnpreencryption {

namespace {

using Clock = std::chrono::high_resolution_clock;

struct Ctx {
    EC_GROUP *group = nullptr;
    BIGNUM *order = nullptr;
    Ctx() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        order = BN_new();
        EC_GROUP_get_order(group, order, nullptr);
    }
    ~Ctx() { BN_free(order); EC_GROUP_free(group); }
};

Ctx &ctx() {
    static Ctx c;
    return c;
}

struct BnCtx {
    BN_CTX *c = BN_CTX_new();
    ~BnCtx() { BN_CTX_free(c); }
};

using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using PtPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

BnPtr bn() { return BnPtr(BN_new(), &BN_clear_free); }
PtPtr pt() { return PtPtr(EC_POINT_new(ctx().group), &EC_POINT_free); }

BnPtr randScalar() {
    BnPtr k = bn();
    do { BN_rand_range(k.get(), ctx().order); } while (BN_is_zero(k.get()));
    return k;
}

BnPtr scalarFrom(const Bytes &b) {
    BnPtr k = bn();
    BN_bin2bn(b.data(), (int)b.size(), k.get());
    return k;
}

Bytes scalarBytes(const BIGNUM *k) {
    Bytes out(32, 0);
    BN_bn2binpad(k, out.data(), 32);
    return out;
}

Bytes pointBytes(const EC_POINT *p, BN_CTX *c) {
    Bytes out(33, 0);
    size_t n = EC_POINT_point2oct(ctx().group, p, POINT_CONVERSION_COMPRESSED,
                                  out.data(), out.size(), c);
    out.resize(n);
    return out;
}

PtPtr pointFrom(const Bytes &b, BN_CTX *c) {
    PtPtr p = pt();
    if (b.empty() || EC_POINT_oct2point(ctx().group, p.get(), b.data(), b.size(), c) != 1)
        return PtPtr(nullptr, &EC_POINT_free);
    return p;
}

// Hash a list of byte strings, with a domain tag, to a scalar in [1, q-1].
BnPtr hashToScalar(const char *tag, std::initializer_list<const Bytes *> parts) {
    SHA256_CTX s;
    SHA256_Init(&s);
    SHA256_Update(&s, tag, std::strlen(tag));
    for (const Bytes *p : parts) SHA256_Update(&s, p->data(), p->size());
    unsigned char d[32];
    SHA256_Final(d, &s);
    BnPtr k = bn();
    BN_bin2bn(d, 32, k.get());
    BnCtx c;
    BN_mod(k.get(), k.get(), ctx().order, c.c);
    if (BN_is_zero(k.get())) BN_one(k.get());
    return k;
}

Bytes kdf(const EC_POINT *shared, BN_CTX *c) {
    Bytes ikm = pointBytes(shared, c);
    Bytes salt(16, 0);
    Bytes info = {'N', 'D', 'N', '-', 'P', 'R', 'E', '-', 'K', 'E', 'M'};
    return CryptoEngine::hkdfSha256(ikm, salt, info, 32);
}

double since(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

} // namespace

Bytes PreReKey::serialize() const {
    Bytes out = rk;
    out.insert(out.end(), X.begin(), X.end());
    return out;
}

PreReKey PreReKey::deserialize(const Bytes &b) {
    PreReKey k;
    if (b.size() < 32 + 33) return k;
    k.rk.assign(b.begin(), b.begin() + 32);
    k.X.assign(b.begin() + 32, b.begin() + 65);
    return k;
}

PreKeyPair UmbralPRE::keygen() {
    BnCtx c;
    PreKeyPair kp;
    BnPtr a = randScalar();
    PtPtr A = pt();
    EC_POINT_mul(ctx().group, A.get(), a.get(), nullptr, nullptr, c.c);
    kp.sk = scalarBytes(a.get());
    kp.pk = pointBytes(A.get(), c.c);
    return kp;
}

PreCapsule UmbralPRE::encapsulate(const Bytes &pkA, Bytes &keyOut, CryptoOpTiming *t) {
    auto t0 = Clock::now();
    BnCtx c;
    PreCapsule cap;
    PtPtr A = pointFrom(pkA, c.c);
    if (!A) throw std::runtime_error("encapsulate: bad public key");
    BnPtr r = randScalar(), u = randScalar();
    PtPtr E = pt(), V = pt();
    EC_POINT_mul(ctx().group, E.get(), r.get(), nullptr, nullptr, c.c);
    EC_POINT_mul(ctx().group, V.get(), u.get(), nullptr, nullptr, c.c);
    cap.E = pointBytes(E.get(), c.c);
    cap.V = pointBytes(V.get(), c.c);
    BnPtr h = hashToScalar("UMBRAL-H2", {&cap.E, &cap.V});
    BnPtr s = bn();
    BN_mod_mul(s.get(), r.get(), h.get(), ctx().order, c.c);
    BN_mod_add(s.get(), s.get(), u.get(), ctx().order, c.c);
    cap.s = scalarBytes(s.get());
    BnPtr ru = bn();
    BN_mod_add(ru.get(), r.get(), u.get(), ctx().order, c.c);
    PtPtr shared = pt();
    EC_POINT_mul(ctx().group, shared.get(), nullptr, A.get(), ru.get(), c.c);
    keyOut = kdf(shared.get(), c.c);
    if (t) t->elapsedSeconds = since(t0);
    return cap;
}

bool UmbralPRE::checkCapsule(const PreCapsule &cap) {
    BnCtx c;
    PtPtr E = pointFrom(cap.E, c.c), V = pointFrom(cap.V, c.c);
    if (!E || !V || cap.s.size() != 32) return false;
    BnPtr s = scalarFrom(cap.s);
    BnPtr h = hashToScalar("UMBRAL-H2", {&cap.E, &cap.V});
    PtPtr lhs = pt(), rhs = pt();
    EC_POINT_mul(ctx().group, lhs.get(), s.get(), nullptr, nullptr, c.c);
    EC_POINT_mul(ctx().group, rhs.get(), nullptr, E.get(), h.get(), c.c);
    EC_POINT_add(ctx().group, rhs.get(), rhs.get(), V.get(), c.c);
    return EC_POINT_cmp(ctx().group, lhs.get(), rhs.get(), c.c) == 0;
}

bool UmbralPRE::decapsulateOriginal(const Bytes &skA, const PreCapsule &cap, Bytes &keyOut) {
    if (!checkCapsule(cap)) return false;
    BnCtx c;
    PtPtr E = pointFrom(cap.E, c.c), V = pointFrom(cap.V, c.c);
    BnPtr a = scalarFrom(skA);
    PtPtr sum = pt();
    EC_POINT_add(ctx().group, sum.get(), E.get(), V.get(), c.c);
    EC_POINT_mul(ctx().group, sum.get(), nullptr, sum.get(), a.get(), c.c);
    keyOut = kdf(sum.get(), c.c);
    return true;
}

PreReKey UmbralPRE::rekeygen(const Bytes &skA, const Bytes &pkB, CryptoOpTiming *t) {
    auto t0 = Clock::now();
    BnCtx c;
    PreReKey out;
    PtPtr B = pointFrom(pkB, c.c);
    if (!B) throw std::runtime_error("rekeygen: bad delegatee key");
    BnPtr a = scalarFrom(skA);
    BnPtr x = randScalar();
    PtPtr X = pt(), xB = pt();
    EC_POINT_mul(ctx().group, X.get(), x.get(), nullptr, nullptr, c.c);
    EC_POINT_mul(ctx().group, xB.get(), nullptr, B.get(), x.get(), c.c);
    out.X = pointBytes(X.get(), c.c);
    Bytes xBb = pointBytes(xB.get(), c.c);
    BnPtr d = hashToScalar("UMBRAL-H3", {&out.X, &pkB, &xBb});
    BnPtr dinv = bn();
    BN_mod_inverse(dinv.get(), d.get(), ctx().order, c.c);
    BnPtr rk = bn();
    BN_mod_mul(rk.get(), a.get(), dinv.get(), ctx().order, c.c);
    out.rk = scalarBytes(rk.get());
    if (t) t->elapsedSeconds = since(t0);
    return out;
}

bool UmbralPRE::reencapsulate(const PreReKey &rk, const PreCapsule &cap,
                              PreCFrag &out, CryptoOpTiming *t) {
    auto t0 = Clock::now();
    if (rk.rk.size() != 32 || !checkCapsule(cap)) {
        if (t) t->elapsedSeconds = since(t0);
        return false;
    }
    BnCtx c;
    PtPtr E = pointFrom(cap.E, c.c), V = pointFrom(cap.V, c.c);
    BnPtr k = scalarFrom(rk.rk);
    PtPtr E1 = pt(), V1 = pt();
    EC_POINT_mul(ctx().group, E1.get(), nullptr, E.get(), k.get(), c.c);
    EC_POINT_mul(ctx().group, V1.get(), nullptr, V.get(), k.get(), c.c);
    out.E1 = pointBytes(E1.get(), c.c);
    out.V1 = pointBytes(V1.get(), c.c);
    out.X = rk.X;
    if (t) t->elapsedSeconds = since(t0);
    return true;
}

bool UmbralPRE::decapsulateFrag(const Bytes &skB, const PreCapsule &cap,
                                const PreCFrag &f, Bytes &keyOut, CryptoOpTiming *t) {
    auto t0 = Clock::now();
    BnCtx c;
    PtPtr E1 = pointFrom(f.E1, c.c), V1 = pointFrom(f.V1, c.c), X = pointFrom(f.X, c.c);
    if (!E1 || !V1 || !X) return false;
    (void)cap;
    BnPtr b = scalarFrom(skB);
    PtPtr B = pt(), bX = pt();
    EC_POINT_mul(ctx().group, B.get(), b.get(), nullptr, nullptr, c.c);
    EC_POINT_mul(ctx().group, bX.get(), nullptr, X.get(), b.get(), c.c);
    Bytes Bb = pointBytes(B.get(), c.c), bXb = pointBytes(bX.get(), c.c);
    BnPtr d = hashToScalar("UMBRAL-H3", {&f.X, &Bb, &bXb});
    PtPtr sum = pt();
    EC_POINT_add(ctx().group, sum.get(), E1.get(), V1.get(), c.c);
    EC_POINT_mul(ctx().group, sum.get(), nullptr, sum.get(), d.get(), c.c);
    keyOut = kdf(sum.get(), c.c);
    if (t) t->elapsedSeconds = since(t0);
    return true;
}

bool UmbralPRE::pointToXY(const Bytes &compressed, Bytes &x, Bytes &y) {
    BnCtx c;
    PtPtr P = pointFrom(compressed, c.c);
    if (!P) return false;
    BnPtr bx = bn(), by = bn();
    EC_POINT_get_affine_coordinates(ctx().group, P.get(), bx.get(), by.get(), c.c);
    x = scalarBytes(bx.get());
    y = scalarBytes(by.get());
    return true;
}

Bytes UmbralPRE::pointFromXY(const Bytes &x, const Bytes &y) {
    BnCtx c;
    BnPtr bx = scalarFrom(x), by = scalarFrom(y);
    PtPtr P = pt();
    if (EC_POINT_set_affine_coordinates(ctx().group, P.get(), bx.get(), by.get(), c.c) != 1)
        return Bytes();
    return pointBytes(P.get(), c.c);
}

} // namespace ndnpreencryption
