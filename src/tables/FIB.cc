#include "FIB.h"
#include <algorithm>

using namespace ndnpreencryption;

FIB::FIB(int size) : maxSize(size)
{
}

FIB::~FIB()
{
    for (auto& pair : routes) {
        for (auto route : pair.second) {
            delete route;
        }
    }
    routes.clear();
}

bool FIB::isCriticalPrefix(const std::string& prefix)
{
    // Check for critical indicators in prefix
    return (prefix.find("critical") != std::string::npos ||
            prefix.find("emergency") != std::string::npos ||
            prefix.find("vitalSigns") != std::string::npos ||
            prefix.find("ICU") != std::string::npos);
}

int FIB::calculatePriority(const std::string& prefix)
{
    if (isCriticalPrefix(prefix)) {
        EV_DEBUG << "FIB: Critical prefix detected: " << prefix << " (priority=3)" << endl;
        return 3; // High priority for critical content
    }
    return 1; // Normal priority
}

std::string FIB::findLongestPrefixMatch(const std::string& contentName)
{
    std::string longestMatch = "";
    size_t longestMatchLength = 0;

    for (const auto& pair : routes) {
        const std::string& prefix = pair.first;
        // Check if contentName starts with this prefix
        if (contentName.find(prefix) == 0) {
            if (prefix.length() > longestMatchLength) {
                longestMatch = prefix;
                longestMatchLength = prefix.length();
            }
        }
    }

    return longestMatch;
}

void FIB::addRoute(const std::string& prefix, int outgoingInterface, double metric)
{
    // Check if route already exists for this prefix and interface
    auto it = routes.find(prefix);
    if (it != routes.end()) {
        for (auto route : it->second) {
            if (route->outgoingInterface == outgoingInterface) {
                // Update existing route
                route->metric = metric;
                route->priority = calculatePriority(prefix);
                route->lastUsed = simTime();
                EV_DEBUG << "FIB: Updated route for prefix " << prefix
                         << " via interface " << outgoingInterface << endl;
                return;
            }
        }
    }

    // Add new route
    int priority = calculatePriority(prefix);
    FIBRoute *newRoute = new FIBRoute(prefix, outgoingInterface, metric, priority);

    if (it != routes.end()) {
        it->second.push_back(newRoute);
    } else {
        std::vector<FIBRoute*> routeList;
        routeList.push_back(newRoute);
        routes[prefix] = routeList;
    }

    EV_DEBUG << "FIB: Added route for prefix " << prefix
             << " via interface " << outgoingInterface
             << " (metric=" << metric << ", priority=" << priority << ")" << endl;
}

void FIB::removeRoute(const std::string& prefix, int outgoingInterface)
{
    auto it = routes.find(prefix);
    if (it != routes.end()) {
        auto& routeList = it->second;
        for (auto routeIt = routeList.begin(); routeIt != routeList.end(); ++routeIt) {
            if ((*routeIt)->outgoingInterface == outgoingInterface) {
                delete *routeIt;
                routeList.erase(routeIt);
                EV_DEBUG << "FIB: Removed route for prefix " << prefix
                         << " via interface " << outgoingInterface << endl;
                break;
            }
        }

        if (routeList.empty()) {
            routes.erase(it);
        }
    }
}

std::vector<int> FIB::getInterfaces(const std::string& contentName)
{
    std::vector<int> interfaces;

    // Find longest prefix match
    std::string matchedPrefix = findLongestPrefixMatch(contentName);

    if (matchedPrefix.empty()) {
        EV_DEBUG << "FIB: No route found for " << contentName << endl;
        return interfaces;
    }

    auto it = routes.find(matchedPrefix);
    if (it != routes.end()) {
        // Sort routes by priority (descending) then by metric (ascending)
        std::vector<FIBRoute*> sortedRoutes = it->second;
        std::sort(sortedRoutes.begin(), sortedRoutes.end(),
                  [](FIBRoute* a, FIBRoute* b) {
                      if (a->priority != b->priority)
                          return a->priority > b->priority; // Higher priority first
                      return a->metric < b->metric; // Lower metric (cost) first
                  });

        for (auto route : sortedRoutes) {
            interfaces.push_back(route->outgoingInterface);
        }

        EV_DEBUG << "FIB: Found " << interfaces.size() << " route(s) for "
                 << contentName << " (matched prefix: " << matchedPrefix << ")" << endl;
    }

    return interfaces;
}

int FIB::getBestInterface(const std::string& contentName)
{
    // Adaptive forwarding strategy: select best interface based on priority and metrics
    std::string matchedPrefix = findLongestPrefixMatch(contentName);

    if (matchedPrefix.empty()) {
        return -1; // No route
    }

    auto it = routes.find(matchedPrefix);
    if (it != routes.end() && !it->second.empty()) {
        // Find route with highest priority and lowest metric
        FIBRoute* bestRoute = it->second[0];

        for (auto route : it->second) {
            if (route->priority > bestRoute->priority ||
                (route->priority == bestRoute->priority && route->metric < bestRoute->metric)) {
                bestRoute = route;
            }
        }

        bestRoute->lastUsed = simTime();

        EV_DEBUG << "FIB: Selected interface " << bestRoute->outgoingInterface
                 << " for " << contentName << " (priority=" << bestRoute->priority
                 << ", metric=" << bestRoute->metric << ")" << endl;

        return bestRoute->outgoingInterface;
    }

    return -1;
}

void FIB::updateMetric(const std::string& prefix, int outgoingInterface, double newMetric)
{
    auto it = routes.find(prefix);
    if (it != routes.end()) {
        for (auto route : it->second) {
            if (route->outgoingInterface == outgoingInterface) {
                route->metric = newMetric;
                EV_DEBUG << "FIB: Updated metric for prefix " << prefix
                         << " via interface " << outgoingInterface
                         << " to " << newMetric << endl;
                return;
            }
        }
    }
}
