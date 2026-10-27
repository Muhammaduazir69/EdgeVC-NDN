package ned;

// Clinician endpoint (or adversary when attackType != "none").
simple Consumer like INdnNode
{
    parameters:
        @display("i=device/laptop;p=$px,$py");
        double px = default(0);    // canvas position (display only)
        double py = default(0);
        string framework = default("didvc");     // none | didvc | didvc_producer | abac | scbac
        string userRole = default("Nurse");
        string unit = default("ICU");
        int clearance = default(3);
        string organization = default("did:self:hospitalX");
        double requestRate @unit(Hz) = default(4Hz);
        double preferredShare = default(0.85);
        double zipfAlpha = default(0.8);
        int catalogSize = default(2000);
        string contentPrefix = default("/hospitalX");
        double breakGlassRate = default(0);
        double interestLifetime @unit(s) = default(4s);
        bool compactPresentation = default(true);
        int extraInterestBytes = default(0);         // diagnostic padding of plain Interests
        int clientCacheSize = default(100);          // records kept decrypted on the device (0 = none)
        bool stopOnRevocation = default(true);       // false: a persistent insider keeps requesting after denial
        double presentationRefresh @unit(s) = default(0s);
        double startTime @unit(s) = default(1s);
        double cpuFactor = default(1.0);
        bool priorityQueueing = default(false);
        string issuerModulePath = default("^.issuer");
        string producerModulePath = default("^.producer");
        string attackType = default("none");   // none | replay | forged_vc | stolen_vc | did_spoof | tampered_vc | no_credential
        double attackRate @unit(Hz) = default(0Hz);
        double attackStart @unit(s) = default(20s);
        string attackVictim = default("");
    gates:
        inout port[];
}
