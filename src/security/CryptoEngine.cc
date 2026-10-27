#include "CryptoEngine.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

namespace ndnpreencryption {

namespace {

class Timer {
public:
    explicit Timer(CryptoOpTiming *t) : out(t) {
        if (out) start = std::chrono::high_resolution_clock::now();
    }
    ~Timer() {
        if (out) {
            auto end = std::chrono::high_resolution_clock::now();
            out->elapsedSeconds =
                std::chrono::duration<double>(end - start).count();
        }
    }
private:
    CryptoOpTiming *out;
    std::chrono::high_resolution_clock::time_point start;
};

[[noreturn]] void throwOpenSSL(const char *what) {
    char buf[256];
    unsigned long err = ERR_get_error();
    ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(std::string("CryptoEngine: ") + what + ": " + buf);
}

} // namespace

void CryptoEngine::initialize() {
    // OpenSSL 1.1+ initializes automatically. ERR_clear_error() is the only
    // safe no-op we want to perform up-front.
    ERR_clear_error();
}

Ed25519KeyPair CryptoEngine::generateEd25519KeyPair() {
    Ed25519KeyPair kp;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) throwOpenSSL("Ed25519 ctx new");
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); throwOpenSSL("Ed25519 keygen init"); }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); throwOpenSSL("Ed25519 keygen"); }
    EVP_PKEY_CTX_free(pctx);

    size_t pubLen = 32, privLen = 32;
    kp.publicKey.resize(pubLen);
    kp.privateKey.resize(privLen);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.publicKey.data(), &pubLen) <= 0) {
        EVP_PKEY_free(pkey); throwOpenSSL("Ed25519 get raw public");
    }
    if (EVP_PKEY_get_raw_private_key(pkey, kp.privateKey.data(), &privLen) <= 0) {
        EVP_PKEY_free(pkey); throwOpenSSL("Ed25519 get raw private");
    }
    EVP_PKEY_free(pkey);
    kp.publicKey.resize(pubLen);
    kp.privateKey.resize(privLen);
    return kp;
}

Bytes CryptoEngine::ed25519Sign(const Bytes &privateKey, const Bytes &message,
                                CryptoOpTiming *timing) {
    Timer t(timing);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                  privateKey.data(), privateKey.size());
    if (!pkey) throwOpenSSL("Ed25519 load private");

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throwOpenSSL("MD_CTX_new"); }

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwOpenSSL("DigestSignInit");
    }

    size_t sigLen = 64;
    Bytes sig(sigLen);
    if (EVP_DigestSign(mdctx, sig.data(), &sigLen,
                       message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throwOpenSSL("DigestSign");
    }
    sig.resize(sigLen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return sig;
}

bool CryptoEngine::ed25519Verify(const Bytes &publicKey, const Bytes &message,
                                 const Bytes &signature,
                                 CryptoOpTiming *timing) {
    Timer t(timing);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                 publicKey.data(), publicKey.size());
    if (!pkey) { ERR_clear_error(); return false; }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return false; }

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); ERR_clear_error(); return false;
    }
    int rc = EVP_DigestVerify(mdctx, signature.data(), signature.size(),
                              message.data(), message.size());
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    if (rc != 1) ERR_clear_error();
    return rc == 1;
}

X25519KeyPair CryptoEngine::generateX25519KeyPair() {
    X25519KeyPair kp;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throwOpenSSL("X25519 ctx new");
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); throwOpenSSL("X25519 keygen init"); }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); throwOpenSSL("X25519 keygen"); }
    EVP_PKEY_CTX_free(pctx);

    size_t pubLen = 32, privLen = 32;
    kp.publicKey.resize(pubLen);
    kp.privateKey.resize(privLen);
    EVP_PKEY_get_raw_public_key(pkey, kp.publicKey.data(), &pubLen);
    EVP_PKEY_get_raw_private_key(pkey, kp.privateKey.data(), &privLen);
    EVP_PKEY_free(pkey);
    kp.publicKey.resize(pubLen);
    kp.privateKey.resize(privLen);
    return kp;
}

Bytes CryptoEngine::x25519SharedSecret(const Bytes &privateKey,
                                       const Bytes &peerPublicKey,
                                       CryptoOpTiming *timing) {
    Timer t(timing);
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                  privateKey.data(), privateKey.size());
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                 peerPublicKey.data(), peerPublicKey.size());
    if (!priv || !peer) {
        EVP_PKEY_free(priv); EVP_PKEY_free(peer); throwOpenSSL("X25519 load keys");
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) { EVP_PKEY_free(priv); EVP_PKEY_free(peer); throwOpenSSL("X25519 derive ctx"); }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv); EVP_PKEY_free(peer);
        throwOpenSSL("X25519 derive init");
    }

    size_t outLen = 32;
    Bytes shared(outLen);
    if (EVP_PKEY_derive(ctx, shared.data(), &outLen) <= 0) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv); EVP_PKEY_free(peer);
        throwOpenSSL("X25519 derive");
    }
    shared.resize(outLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return shared;
}

AeadCiphertext CryptoEngine::aesGcmEncrypt(const Bytes &key, const Bytes &plaintext,
                                           const Bytes &aad,
                                           CryptoOpTiming *timing) {
    Timer t(timing);
    if (key.size() != 32) throw std::runtime_error("AES-GCM requires 32-byte key");

    AeadCiphertext result;
    result.iv = randomBytes(12);
    result.ciphertext.resize(plaintext.size());
    result.tag.resize(16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSL("AES-GCM ctx new");
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("EncryptInit alg");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("Set IVLEN");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("EncryptInit key/iv");
    }

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx); throwOpenSSL("AAD");
        }
    }
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("EncryptUpdate");
    }
    int outLen = len;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + outLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("EncryptFinal");
    }
    outLen += len;
    result.ciphertext.resize(outLen);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throwOpenSSL("GET_TAG");
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

Bytes CryptoEngine::aesGcmDecrypt(const Bytes &key, const AeadCiphertext &ct,
                                  const Bytes &aad, CryptoOpTiming *timing) {
    Timer t(timing);
    if (key.size() != 32) throw std::runtime_error("AES-GCM requires 32-byte key");

    Bytes plaintext(ct.ciphertext.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSL("AES-GCM ctx new");
    int len = 0, plainLen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("DecryptInit alg"); }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ct.iv.size(), nullptr) != 1)
    { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("Set IVLEN"); }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), ct.iv.data()) != 1)
    { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("DecryptInit key/iv"); }

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("AAD"); }
    }
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ct.ciphertext.data(), ct.ciphertext.size()) != 1)
    { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("DecryptUpdate"); }
    plainLen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct.tag.size(),
                            const_cast<uint8_t*>(ct.tag.data())) != 1)
    { EVP_CIPHER_CTX_free(ctx); throwOpenSSL("SET_TAG"); }

    int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + plainLen, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) throw std::runtime_error("AES-GCM tag verification failed");
    plainLen += len;
    plaintext.resize(plainLen);
    return plaintext;
}

Bytes CryptoEngine::sha256(const Bytes &data, CryptoOpTiming *timing) {
    Timer t(timing);
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

Bytes CryptoEngine::sha256(const std::string &data, CryptoOpTiming *timing) {
    Bytes b(data.begin(), data.end());
    return sha256(b, timing);
}

Bytes CryptoEngine::hkdfSha256(const Bytes &ikm, const Bytes &salt,
                               const Bytes &info, size_t length,
                               CryptoOpTiming *timing) {
    Timer t(timing);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throwOpenSSL("HKDF ctx new");

    Bytes out(length);
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx); throwOpenSSL("HKDF params");
    }
    size_t outLen = length;
    if (EVP_PKEY_derive(pctx, out.data(), &outLen) <= 0) {
        EVP_PKEY_CTX_free(pctx); throwOpenSSL("HKDF derive");
    }
    out.resize(outLen);
    EVP_PKEY_CTX_free(pctx);
    return out;
}

ReWrappedKey CryptoEngine::preReEncryptDek(const Bytes &delegatorEphemeralPriv,
                                           const Bytes &recipientX25519Pub,
                                           const Bytes &originalDek,
                                           CryptoOpTiming *timing) {
    Timer t(timing);
    // PRE re-encryption proxy step: produce a fresh wrap of the DEK for the
    // recipient's X25519 public key. Cost profile mirrors a single-hop
    // unidirectional PRE: one scalar multiplication + KDF + AEAD wrap.

    // 1. ECDH between delegator's ephemeral private and recipient's static pub.
    Bytes shared = x25519SharedSecret(delegatorEphemeralPriv, recipientX25519Pub);
    // 2. HKDF to a 32-byte wrap key.
    Bytes salt(16, 0);                                // fixed salt for the scheme
    Bytes info = {'N', 'D', 'N', '-', 'P', 'R', 'E'}; // domain separation
    Bytes wrapKey = hkdfSha256(shared, salt, info, 32);
    // 3. AES-GCM wrap the original DEK.
    AeadCiphertext wrapped = aesGcmEncrypt(wrapKey, originalDek);

    ReWrappedKey out;
    out.wrappedKey = wrapped.ciphertext;
    out.iv = wrapped.iv;
    out.tag = wrapped.tag;
    // Recipient needs delegator's ephemeral public key to reproduce the shared
    // secret. We don't have the public counterpart cached here, so we recompute
    // it via the OpenSSL pkey routine. This adds the realistic cost of
    // exporting an ephemeral pubkey on the proxy side.
    EVP_PKEY *ephPriv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                     delegatorEphemeralPriv.data(),
                                                     delegatorEphemeralPriv.size());
    if (ephPriv) {
        size_t pubLen = 32;
        out.ephemeralPublicKey.resize(pubLen);
        EVP_PKEY_get_raw_public_key(ephPriv, out.ephemeralPublicKey.data(), &pubLen);
        out.ephemeralPublicKey.resize(pubLen);
        EVP_PKEY_free(ephPriv);
    }
    return out;
}

Bytes CryptoEngine::randomBytes(size_t n) {
    Bytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throwOpenSSL("RAND_bytes");
    }
    return out;
}

std::string CryptoEngine::toBase64Url(const Bytes &data) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | uint32_t(data[i+2]);
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
    }
    if (i < data.size()) {
        uint32_t v = uint32_t(data[i]) << 16;
        if (i + 1 < data.size()) v |= uint32_t(data[i+1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        if (i + 1 < data.size()) out.push_back(tbl[(v >> 6) & 0x3F]);
        // RFC 7515 base64url: no padding.
    }
    return out;
}

Bytes CryptoEngine::fromBase64Url(const std::string &b64) {
    static int8_t map[256];
    static bool initd = false;
    if (!initd) {
        for (int i = 0; i < 256; i++) map[i] = -1;
        const char *tbl =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 64; i++) map[(uint8_t)tbl[i]] = (int8_t)i;
        initd = true;
    }
    Bytes out;
    out.reserve(b64.size() * 3 / 4);
    uint32_t v = 0;
    int nbits = 0;
    for (char c : b64) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int8_t d = map[(uint8_t)c];
        if (d < 0) continue;
        v = (v << 6) | d;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out.push_back(uint8_t((v >> nbits) & 0xFF));
        }
    }
    return out;
}

std::string CryptoEngine::toHex(const Bytes &data) {
    static const char hex[] = "0123456789abcdef";
    std::string out(data.size() * 2, '0');
    for (size_t i = 0; i < data.size(); i++) {
        out[2*i]   = hex[(data[i] >> 4) & 0xF];
        out[2*i+1] = hex[data[i] & 0xF];
    }
    return out;
}

} // namespace ndnpreencryption
