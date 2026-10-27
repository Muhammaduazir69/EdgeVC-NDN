#ifndef __NDNPREENCRYPTION_CONTENTSTORE_H_
#define __NDNPREENCRYPTION_CONTENTSTORE_H_

#include <omnetpp.h>
#include <list>
#include <string>
#include <unordered_map>
#include "../messages/NDNMessages_m.h"

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * Content Store with least-recently-used replacement (the default policy
 * of NFD). Entries are owned by the store; lookups return a borrowed
 * pointer that stays valid until the next insert.
 */
class ContentStore {
  public:
    explicit ContentStore(int capacity) : cap(capacity) {}
    ~ContentStore() { clear(); }
    DataPacket *lookup(const std::string &name);
    void insert(const std::string &name, DataPacket *d);   // takes ownership
    void clear();
    int size() const { return (int)index.size(); }
    long evictions() const { return evicted; }
  private:
    int cap;
    long evicted = 0;
    std::list<std::string> lru;
    std::unordered_map<std::string, std::pair<DataPacket *, std::list<std::string>::iterator>> index;
};

} // namespace ndnpreencryption

#endif
