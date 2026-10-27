cplusplus {{
#include <omnetpp.h>
}}

//
// Wire model. Byte lengths are set by the sender from the binary NDN-TLV
// size of every field (JSON credentials count at their serialized length,
// signatures and EC points at their raw size), not from these strings.
//

packet NDNPacket
{
    string contentName;
    simtime_t timestamp;
}

// Presentation modes for the consumer's credential.
//   0 = none (plain NDN, or upstream of the enforcement point)
//   1 = full    : DID document + VC carried in the Interest
//   2 = compact : DID + VC id only; the edge holds a verified session
enum PresentationMode { PRES_NONE = 0; PRES_FULL = 1; PRES_COMPACT = 2; }

packet InterestPacket extends NDNPacket
{
    int     nonce;
    double  lifetime = 4.0;
    string  requesterId;        // DID (didvc) or enrolled user id (abac, scbac)
    int64_t signingTimestamp;
    string  nonceHex;
    string  signatureValue;     // base64url Ed25519 over canonical bytes
    int     presentationMode = 0;
    string  didDocJson;
    string  vcJson;
    string  vcId;
    bool    breakGlass = false;
    bool    attack = false;     // ground-truth tag for adversarial traffic
    int     originConsumer = -1;// module id; used only for accounting
    double  hopDepartTimeSec = 0;
}

packet DataPacket extends NDNPacket
{
    double  freshnessPeriod = 300;
    bool    isCritical = false;
    bool    encrypted = false;
    string  ciphertext;          // base64url AES-256-GCM(DEK, FHIR JSON)
    string  iv;
    string  tag;
    string  capsuleE;            // PRE capsule (base64url compressed points)
    string  capsuleV;
    string  capsuleS;
    string  cfragE1;             // per-consumer re-encapsulation fragment
    string  cfragV1;
    string  cfragX;
    string  signature;           // producer Ed25519 over name|ct|capsule
    int     plainSize;
    int     recipient = -1;      // consumer module id (set at the edge)
    int     pitToken = 0;        // NDNLPv2 PIT token on the access hop: the
                                 // nonce of the consumer Interest this copy answers
    bool    noCache = false;     // personalized copy: routers must not cache it
    int     fetchedFor = -1;     // consumer whose request brought it into a CS
    bool    keyOnly = false;     // key-split baseline: kappa' only, no ciphertext
}

// NACK reasons:
//   0 no route / no content   1 congestion
//   2 access denied (signature, policy, forged credential)
//   3 credential suspended    4 credential revoked     5 credential expired
//   6 presentation required (compact reference unknown at this edge)
//   7 authorization service unavailable (PDP / quorum timeout)
//   8 replay detected
packet NACKPacket extends NDNPacket
{
    int    reason;
    int    nonce;
    string details;
}

//
// Control plane. Routed hop by hop on module ids with shortest-path tables
// built at initialization. In a deployment these are signed command
// Interests and their Data replies; sizes are set to that encoding.
//
packet CtrlPacket
{
    int srcId;
    int dstId;
}

// Credential issuance / enrollment (consumer -> issuer).
packet VCIssueRequest extends CtrlPacket
{
    string requesterId;
    string didDocJson;
    string signingPublicKey;     // base64url Ed25519
    string prePublicKey;         // base64url compressed P-256 point
    string requestedRole;
    string requestedUnit;
    string organization;
    int    clearance;
    int    nonce;
    string signatureValue;
}

packet VCIssueResponse extends CtrlPacket
{
    bool   success;
    string requesterId;
    string vcJson;               // didvc only
    string reason;
}

// Authorization query from an edge PEP to a PDP (abac) or to one validator
// (scbac endorsement).
packet AuthzRequest extends CtrlPacket
{
    int64_t reqId;
    string  requesterId;
    string  contentName;
    string  signedBytes;
    string  signatureValue;
    bool    breakGlass;
}

packet AuthzResponse extends CtrlPacket
{
    int64_t reqId;
    bool    granted;
    int     denyReason;
    string  requesterId;
    string  signingPublicKey;
    string  sealedReKey;
    string  decisionSig;         // responder Ed25519 over the decision
    string  responderKeyId;
    int64_t ledgerVersion;
}

// Identity / status update from the issuer to the PDP (abac) or a
// transaction to the validator set (scbac).
packet IdentityUpdate extends CtrlPacket
{
    string  userId;
    string  signingPublicKey;
    string  role;
    string  unit;
    int     clearance;
    string  sealedReKey;
    int     status;              // 0 active, 1 revoked, 2 suspended
    int64_t seq;
    double  submittedAt;
}

// Break-glass audit record: an edge that grants under the emergency rule
// signs what it granted and sends it to the issuer.
packet AuditRecord extends CtrlPacket
{
    string requesterId;
    string contentName;
    double grantedAt;
    string edgeSig;
}

// DID+VC status-list dissemination (flooded with per-version dedup).
packet VCListDeltaPacket
{
    string  deltaJson;
    int     listVersion;
    double  issuedAtSim;
}

packet VCListSnapshotPacket
{
    string  snapshotJson;
    int     listVersion;
    double  issuedAtSim;
}

// Status-list pull: one hop after a version gap (dstId = neighbour), or
// end to end to the issuer in the periodic-pull variant.
packet VCListSyncRequest extends CtrlPacket
{
    int knownVersion;
}

packet StatusSyncResponse extends CtrlPacket
{
    string snapshotJson;
    string deltasJson;           // JSON array of deltas newer than the snapshot
    int    listVersion;
}
