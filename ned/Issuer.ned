package ned;

// Hospital credential authority and data owner.
simple Issuer like INdnNode
{
    parameters:
        @display("i=device/server2");
        string framework = default("didvc");
        double snapshotInterval @unit(s) = default(30s);
        double vcValidity @unit(s) = default(86400s);
        double reactivationDelay @unit(s) = default(60s);
        double revocationRate = default(0);       // events per second (Poisson)
        double suspensionRate = default(0);
        string revocationTimes = default("");     // explicit schedule, e.g. "100,200"
        double lifecycleStart @unit(s) = default(20s);
        string statusDissemination = default("push");
        string statusListName = default("/hospitalX/status/v1");
        bool pushInvalidation = default(false);    // abac/scbac: push status changes to edge PEP caches
        double failAt @unit(s) = default(-1s);     // credential authority offline from failAt to recoverAt
        double recoverAt @unit(s) = default(-1s);
    gates:
        inout port[];
}
