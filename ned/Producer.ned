package ned;

// EHR repository: encrypt-once FHIR content with a PRE capsule.
simple Producer like INdnNode
{
    parameters:
        int extraDataBytes = default(0);             // diagnostic padding of plain Data
        @display("i=device/server");
        string framework = default("didvc");
        string contentPrefix = default("/hospitalX");
        string fhirCorpusDir = default("");
        double cpuFactor = default(1.0);
        bool priorityQueueing = default(false);
        string issuerModulePath = default("^.issuer");
        int sessionCapacity = default(4096);
        double replayWindow @unit(s) = default(30s);
    gates:
        inout port[];
}
