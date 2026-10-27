#include "ContentStore.h"

namespace ndnpreencryption {

DataPacket *ContentStore::lookup(const std::string &name) {
    auto it = index.find(name);
    if (it == index.end()) return nullptr;
    lru.splice(lru.begin(), lru, it->second.second);
    return it->second.first;
}

void ContentStore::insert(const std::string &name, DataPacket *d) {
    if (cap <= 0) { delete d; return; }
    auto it = index.find(name);
    if (it != index.end()) {
        delete it->second.first;
        it->second.first = d;
        lru.splice(lru.begin(), lru, it->second.second);
        return;
    }
    lru.push_front(name);
    index.emplace(name, std::make_pair(d, lru.begin()));
    while ((int)index.size() > cap) {
        auto victim = index.find(lru.back());
        delete victim->second.first;
        index.erase(victim);
        lru.pop_back();
        evicted++;
    }
}

void ContentStore::clear() {
    for (auto &kv : index) delete kv.second.first;
    index.clear();
    lru.clear();
}

} // namespace ndnpreencryption
