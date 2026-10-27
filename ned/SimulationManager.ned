package ned;

simple SimulationManager
{
    parameters:
        @display("i=block/control");
        string scenarioName = default("");
        string label = default("");
        string framework = default("didvc");
        double warmup @unit(s) = default(20s);
        string outputPrefix = default("results/run");
        bool detailedLogs = default(false);
        string costModelFile = default("");
        string costReportFile = default("");
}
