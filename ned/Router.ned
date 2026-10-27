package ned;

// NDN forwarder; edge routers enforce access control and act as PRE proxy.
simple Router like INdnNode
{
    parameters:
        @display("i=abstract/router");
        string framework = default("didvc");
        string contentPrefix = default("/hospitalX");
        int csSize = default(500);
        int pitSize = default(4000);
        double suppressionInterval @unit(s) = default(250ms);
        double forwardingDelay @unit(s) = default(50us);
        double cpuFactor = default(1.0);
        double authzTimeout @unit(s) = default(2s);
        double decisionCacheTtl @unit(s) = default(0s);
        bool speculativeFetch = default(false);      // PEP fetches the record while the decision is pending
        int sessionCapacity = default(1024);
        double replayWindow @unit(s) = default(30s);
        string statusDissemination = default("push");   // push | pull
        double pullInterval @unit(s) = default(10s);
        double statusBeacon @unit(s) = default(1s);      // anti-entropy period (0 = off)
        double gapGrace @unit(s) = default(50ms);
        double statusMaxAge @unit(s) = default(300s);   // fail closed if no verified status update for this long (0 = off)
        bool priorityQueueing = default(false);
        string issuerModulePath = default("^.issuer");
        // UDP-face deployments (5G): faces >= consumerFaceStart are clinician
        // faces, upstreamFaces is the FIB toward the producer, ctrlRoutes maps
        // control destinations to faces. Defaults: discover from the topology.
        int consumerFaceStart = default(-1);
        string upstreamFaces = default("");
        string ctrlRoutes = default("");
        int defaultCtrlFace = default(-1);
    gates:
        inout port[];
}
