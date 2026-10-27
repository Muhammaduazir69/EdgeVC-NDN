package ned;

// Central PDP (abac) or ledger validator (scbac).
simple AuthzServer like INdnNode
{
    parameters:
        @display("i=block/encrypt");
        string mode = default("pdp");             // pdp | validator
        double blockInterval @unit(s) = default(2s);
        double cpuFactor = default(1.0);
        double failAt @unit(s) = default(-1s);
        double recoverAt @unit(s) = default(-1s);
    gates:
        inout port[];
}
