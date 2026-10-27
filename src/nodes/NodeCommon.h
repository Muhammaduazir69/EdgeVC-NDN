#ifndef __NDNPREENCRYPTION_NODECOMMON_H_
#define __NDNPREENCRYPTION_NODECOMMON_H_

#include <omnetpp.h>
#include <map>
#include <string>
#include <vector>

#include "../messages/NDNMessages_m.h"
#include "../utils/MetricsCollector.h"

using namespace omnetpp;

namespace ndnpreencryption {

// Binary NDN-TLV size of the fixed part of an Interest (type/length octets,
// nonce, lifetime, hop limit) excluding the name and signature fields.
constexpr int kInterestFixed = 16;
// Signature info + value of a signed Interest: key locator (counted with the
// requester id), timestamp, 128-bit nonce, Ed25519 signature.
constexpr int kInterestSigFixed = 8 + 16 + 64 + 8;
constexpr int kDataFixed = 24;
constexpr int kNackBytes = 48;

// Byte accounting of one packet into ByteClass buckets.
void classifyBytes(cPacket *pkt, std::vector<std::pair<ByteClass, long>> &out);

/**
 * Per-gate FIFO transmit queues with optional strict priority for
 * break-glass traffic. Waits for the DatarateChannel to become idle
 * instead of throwing "channel busy", stamps Interests with their actual
 * departure time, and charges every transmitted byte to its class.
 */
class GateTx {
  public:
    void init(cSimpleModule *owner, const char *gateBase, bool priority);
    void send(cPacket *pkt, int gateIndex);
    bool handleTimer(cMessage *msg);
    void clear();
    int  size() const { return (int)queues.size(); }
    long dropped() const { return drops; }
    void setQueueLimit(int pkts) { limit = pkts; }

  private:
    void trySend(int g);
    cSimpleModule *owner = nullptr;
    std::string gateBase;
    bool priority = false;
    int limit = 0;
    long drops = 0;
    struct Q { cQueue hi, lo; cMessage *timer = nullptr; };
    std::vector<Q *> queues;
};

// Shortest-path (hop count) next-hop table from `self` to every module
// reachable over "port" gates, crossing only Router modules as transit.
std::map<int, int> buildControlRoutes(cModule *self);

// Link loss. Interests, Data, NACKs and flooded status packets are lost
// outright; control exchanges ride a reliable transport and are delivered
// again after one retransmission timeout. Returns true when the caller must
// stop processing `msg` (dropped, or rescheduled for redelivery).
bool handleLinkLoss(cSimpleModule *m, cMessage *msg, double rto = 0.2);
// True for a packet that handleLinkLoss rescheduled (it is a network
// arrival, not a timer); clears the marker.
bool takeRedelivery(cMessage *msg);

bool isRouterModule(cModule *m);
bool isConsumerModule(cModule *m);
cModule *peerOfGate(cModule *self, int gateIndex);

// Find all submodules of the network whose NED type name contains `type`.
std::vector<cModule *> findModulesByType(cModule *anyModule, const char *type);

} // namespace ndnpreencryption

#endif
