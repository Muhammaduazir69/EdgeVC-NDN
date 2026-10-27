#ifndef __NDNPREENCRYPTION_NDNUDPFACE_H_
#define __NDNPREENCRYPTION_NDNUDPFACE_H_

#include <omnetpp.h>
#include <string>
#include <vector>

#include <inet/networklayer/common/L3Address.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>

using namespace omnetpp;

namespace ndnpreencryption {

/**
 * NDN-over-UDP face adapter (in the spirit of NFD's UDP unicast faces).
 * Gate ndn[i] of this module is face i of the NDN node next to it inside
 * the same INET application. The first `staticRemotes` faces are bound to
 * configured host:port endpoints; the remaining faces are bound, in order
 * of first contact, to new remote endpoints (clinician UEs).
 */
class NdnUdpFace : public cSimpleModule {
  protected:
    virtual int numInitStages() const override;
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
  private:
    inet::UdpSocket socket;
    int localPort = 0;
    std::vector<std::string> staticSpecs;
    std::vector<inet::L3Address> addr;
    std::vector<int> port;
    int nFaces = 0;
    long rx = 0, txCount = 0, unknownDropped = 0;
};

} // namespace ndnpreencryption

#endif
