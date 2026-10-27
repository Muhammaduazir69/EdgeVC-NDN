#ifndef __NDNPREENCRYPTION_STATUSLIST_H_
#define __NDNPREENCRYPTION_STATUSLIST_H_

#include <map>
#include <string>
#include <vector>
#include "CryptoEngine.h"

namespace ndnpreencryption {

// Two-bit status per credential index (W3C Bitstring Status List with a
// status size of 2: 0 active, 1 revoked, 2 suspended).
enum class CredStatus : uint8_t { ACTIVE = 0, REVOKED = 1, SUSPENDED = 2 };

const char *credStatusName(CredStatus s);

struct StatusDelta {
    std::string issuerDid;
    int  baseVersion = 0;
    int  newVersion = 0;
    int  index = -1;
    CredStatus status = CredStatus::ACTIVE;
    long long issuedAt = 0;
    Bytes signature;

    std::string signingInput() const;
    std::string toJson() const;
    static StatusDelta fromJson(const std::string &json);
    void sign(const Bytes &sk);
    bool verify(const Bytes &pk, CryptoOpTiming *t = nullptr) const;
};

struct StatusSnapshot {
    std::string issuerDid;
    std::string listName;
    int  version = 0;
    int  size = 0;
    long long issuedAt = 0;
    std::string encodedList;     // base64url of the packed 2-bit list
    Bytes signature;

    std::string signingInput() const;
    std::string toJson() const;
    static StatusSnapshot fromJson(const std::string &json);
    void sign(const Bytes &sk);
    bool verify(const Bytes &pk, CryptoOpTiming *t = nullptr) const;
};

/**
 * Replica of the issuer's status list. Deltas must arrive in version
 * order; a gap (newVersion > version + 1) is reported to the caller, which
 * pulls a snapshot from a neighbour. Unknown indices read as ACTIVE because
 * a credential that verifies under the issuer key and is absent from the
 * list has never had its status changed.
 */
class StatusList {
  public:
    enum class ApplyResult { APPLIED, STALE, GAP, BAD_SIGNATURE };

    int  version() const { return currentVersion; }
    CredStatus lookup(int index) const;
    void set(int index, CredStatus s);           // issuer side only
    void bumpVersion() { currentVersion++; }

    ApplyResult applyDelta(const StatusDelta &d, const Bytes &issuerPk,
                           CryptoOpTiming *t = nullptr);
    ApplyResult applySnapshot(const StatusSnapshot &s, const Bytes &issuerPk,
                              CryptoOpTiming *t = nullptr);

    StatusSnapshot buildSnapshot(const std::string &issuerDid,
                                 const std::string &listName,
                                 long long issuedAt) const;
    int size() const { return (int)statuses.size(); }

  private:
    int currentVersion = 0;
    std::vector<uint8_t> statuses;   // one byte per index in memory
};

} // namespace ndnpreencryption

#endif
