package ned;

import inet.applications.contract.IApp;

// INET application that hosts one NDN node behind a UDP face adapter.
module NdnApp like IApp
{
    parameters:
        @display("i=block/app");
        string nodeType;        // Consumer | Router | Producer | Issuer | AuthzServer
        int numFaces = default(1);
        int localPort;
        string remotes = default("");
    gates:
        input socketIn;
        output socketOut;
    submodules:
        face: NdnUdpFace {
            localPort = parent.localPort;
            remotes = parent.remotes;
        }
        node: <nodeType> like INdnNode;
    connections:
        socketIn --> face.socketIn;
        face.socketOut --> socketOut;
        for i=0..numFaces-1 {
            node.port$o++ --> ned.DatarateChannel { datarate = 100Gbps; delay = 0s; } --> face.ndn$i++;
            node.port$i++ <-- face.ndn$o++;
        }
}
