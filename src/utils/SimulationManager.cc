#include "SimulationManager.h"

#include <fstream>

#include "../security/EnforcementEngine.h"

namespace ndnpreencryption {

Define_Module(SimulationManager);

void SimulationManager::initialize() {
    MetricsCollector *m = MetricsCollector::getInstance();
    m->reset(par("framework").stdstringValue(), par("warmup").doubleValue());
    cConfigurationEx *cfg = getEnvir()->getConfigEx();
    m->setMeta("scenario", par("scenarioName").stdstringValue());
    m->setMeta("config", cfg->getVariable(CFGVAR_CONFIGNAME));
    m->setMeta("run", cfg->getVariable(CFGVAR_RUNNUMBER));
    m->setMeta("repetition", cfg->getVariable(CFGVAR_REPETITION));
    m->setMeta("itervars", cfg->getVariable(CFGVAR_ITERATIONVARSF));
    m->setMeta("label", par("label").stdstringValue());

    CostModel &cm = CostModel::instance();
    cm.loadOrCalibrate(par("costModelFile").stdstringValue());
    std::string rep = par("costReportFile").stdstringValue();
    if (!rep.empty()) { std::ofstream f(rep); f << cm.report(); }

    if (!registered) { getEnvir()->addLifecycleListener(this); registered = true; }
}

void SimulationManager::lifecycleEvent(SimulationLifecycleEventType type, cObject *) {
    if (type != LF_POST_NETWORK_FINISH) return;
    MetricsCollector::getInstance()->exportAll(par("outputPrefix").stdstringValue(),
                                               par("detailedLogs").boolValue());
}

SimulationManager::~SimulationManager() {
    if (registered) getEnvir()->removeLifecycleListener(this);
}

} // namespace ndnpreencryption
