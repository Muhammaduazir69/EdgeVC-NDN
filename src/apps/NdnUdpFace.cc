#include "NdnUdpFace.h"

#include <sstream>

#include <inet/common/INETDefs.h>
#include <inet/common/packet/Packet.h>
#include <inet/common/packet/chunk/cPacketChunk.h>
#include <inet/networklayer/common/L3AddressResolver.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/transportlayer/common/L4PortTag_m.h>

using namespace inet;

namespace ndnpreencryption {

Define_Module(NdnUdpFace);

int NdnUdpFace::numInitStages() const { return NUM_INIT_STAGES; }

void NdnUdpFace::initialize(int stage) {
    if (stage == INITSTAGE_LOCAL) {
        localPort = par("localPort").intValue();
        nFaces = gateSize("ndn");
        std::istringstream ss(par("remotes").stdstringValue());
        std::string tok;
        while (ss >> tok) staticSpecs.push_back(tok);
        addr.assign(nFaces, L3Address());
        port.assign(nFaces, -1);
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        socket.setOutputGate(gate("socketOut"));
        socket.bind(localPort);
        for (size_t i = 0; i < staticSpecs.size() && (int)i < nFaces; i++) {
            size_t c = staticSpecs[i].rfind(':');
            addr[i] = L3AddressResolver().resolve(staticSpecs[i].substr(0, c).c_str());
            port[i] = std::stoi(staticSpecs[i].substr(c + 1));
        }
    }
}

void NdnUdpFace::handleMessage(cMessage *msg) {
    if (msg->arrivedOn("socketIn")) {
        auto *pkt = dynamic_cast<Packet *>(msg);
        if (!pkt) { delete msg; return; }
        L3Address src = pkt->getTag<L3AddressInd>()->getSrcAddress();
        int sport = pkt->getTag<L4PortInd>()->getSrcPort();
        int face = -1;
        for (int i = 0; i < nFaces; i++)
            if (port[i] == sport && addr[i] == src) { face = i; break; }
        if (face < 0)
            for (int i = (int)staticSpecs.size(); i < nFaces; i++)
                if (port[i] < 0) { addr[i] = src; port[i] = sport; face = i; break; }
        if (face < 0) { unknownDropped++; delete msg; return; }
        auto chunk = pkt->peekAtFront<cPacketChunk>();
        cPacket *inner = chunk->getPacket()->dup();
        delete pkt;
        rx++;
        send(inner, "ndn$o", face);
        return;
    }
    // From the NDN node: face index = arrival gate index.
    int face = msg->getArrivalGate()->getIndex();
    if (face < 0 || face >= nFaces || port[face] < 0) { delete msg; return; }
    cPacket *ndn = check_and_cast<cPacket *>(msg);
    auto *pkt = new Packet(ndn->getName());
    pkt->insertAtBack(makeShared<cPacketChunk>(ndn));
    socket.sendTo(pkt, addr[face], port[face]);
    txCount++;
}

void NdnUdpFace::finish() {
    recordScalar("udpRx", rx);
    recordScalar("udpTx", txCount);
    recordScalar("unknownDropped", unknownDropped);
}

} // namespace ndnpreencryption
