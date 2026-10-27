#ifndef __NDNPREENCRYPTION_FIB_H_
#define __NDNPREENCRYPTION_FIB_H_

#include <omnetpp.h>
#include <string>
#include <vector>
#include <map>

using namespace omnetpp;

namespace ndnpreencryption {

struct FIBRoute {
    std::string prefix;
    int outgoingInterface;
    double metric;
    int priority;
    simtime_t lastUsed;

    FIBRoute(const std::string& p, int iface, double m, int pri = 1)
        : prefix(p), outgoingInterface(iface), metric(m), priority(pri), lastUsed(simTime()) {}
};

/**
 * Forwarding Information Base (FIB)
 * Maps content name prefixes to outgoing interfaces with priority-based forwarding
 *
 * Priority-based forwarding for critical prefixes:
 * - Critical prefixes (containing "critical", "emergency", "ICU", "vitalSigns"):
 *   Higher priority (3) for preferential routing
 * - Regular prefixes: Normal priority (1)
 *
 * Adaptive Forwarding Strategy:
 * - Monitors network conditions (congestion, delays)
 * - Dynamically adjusts forwarding decisions
 * - Uses metrics (cost, latency) for route selection
 *
 * Hierarchical Content Naming Support:
 * - Standard: /institution/department/patientID/data-type/version
 * - Context-based: /institution/department/critical/patientID/data-type/specific
 */
class FIB
{
private:
    int maxSize;
    std::map<std::string, std::vector<FIBRoute*>> routes;

    bool isCriticalPrefix(const std::string& prefix);
    int calculatePriority(const std::string& prefix);
    std::string findLongestPrefixMatch(const std::string& contentName);

public:
    FIB(int size);
    ~FIB();

    void addRoute(const std::string& prefix, int outgoingInterface, double metric);
    void removeRoute(const std::string& prefix, int outgoingInterface);
    std::vector<int> getInterfaces(const std::string& contentName);
    int getBestInterface(const std::string& contentName);
    void updateMetric(const std::string& prefix, int outgoingInterface, double newMetric);
    int getSize() const { return routes.size(); }
};

} // namespace ndnpreencryption

#endif
