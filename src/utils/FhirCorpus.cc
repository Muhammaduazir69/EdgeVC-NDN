#include "FhirCorpus.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

namespace ndnpreencryption {

// The set of FHIR resource types we know how to load. The NDJSON filename
// convention from the SMART-on-FHIR sample-bulk-fhir-datasets repo is
// "<ResourceType>.000.ndjson".
static const char *KNOWN_TYPES[] = {
    "Patient", "Observation", "Condition", "MedicationRequest",
    "DiagnosticReport", "Encounter", "AllergyIntolerance", "Procedure",
    "Immunization", "DocumentReference", "ServiceRequest", "Specimen",
    "Practitioner", "Organization", "Location", nullptr
};

FhirCorpus &FhirCorpus::instance(const std::string &rootDir) {
    static FhirCorpus inst;
    if (!inst.loaded && !rootDir.empty())
        inst.loadOnce(rootDir);
    return inst;
}

static bool fileExists(const std::string &path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

void FhirCorpus::loadOneType(const std::string &resourceType,
                              const std::string &path) {
    std::ifstream in(path);
    if (!in.is_open()) return;

    std::vector<std::string> &bucket = resourcesByType[resourceType];
    bucket.reserve(256);

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        // Sanity: every NDJSON line must start with '{' and end with '}'.
        if (line.front() != '{' || line.back() != '}') continue;
        bucket.push_back(std::move(line));
    }
}

void FhirCorpus::loadOnce(const std::string &rootDir) {
    if (loaded) return;
    root = rootDir;

    for (int i = 0; KNOWN_TYPES[i] != nullptr; ++i) {
        const std::string type = KNOWN_TYPES[i];
        const std::string path = rootDir + "/" + type + ".000.ndjson";
        if (fileExists(path))
            loadOneType(type, path);
    }

    loaded = true;
    if (!resourcesByType.empty()) {
        std::cerr << "[FhirCorpus] loaded from " << rootDir << ": ";
        for (auto &kv : resourcesByType)
            std::cerr << kv.first << "=" << kv.second.size() << " ";
        std::cerr << std::endl;
    }
    else {
        std::cerr << "[FhirCorpus] no NDJSON files found under " << rootDir
                  << " — generator will synthesize content" << std::endl;
    }
}

std::size_t FhirCorpus::countOf(const std::string &resourceType) const {
    auto it = resourcesByType.find(resourceType);
    return (it == resourcesByType.end()) ? 0 : it->second.size();
}

std::size_t FhirCorpus::totalLoaded() const {
    std::size_t t = 0;
    for (auto &kv : resourcesByType) t += kv.second.size();
    return t;
}

// Rewrite subject.reference and id fields so simulation traceability holds:
// each Data packet's payload references the same simulated patient ID that
// appears in the NDN content name. We do this with a single string-replace
// pass because the source resources are well-formed JSON with predictable
// shapes.
static std::string rewriteForPatient(const std::string &resourceJson,
                                     const std::string &resourceType,
                                     const std::string &overridePatientId) {
    if (overridePatientId.empty()) return resourceJson;

    std::string out = resourceJson;

    // Find "subject":{"reference":"Patient/<...>"} and replace just the id.
    const std::string SUBJ = "\"subject\":{\"reference\":\"Patient/";
    std::size_t sp = out.find(SUBJ);
    if (sp != std::string::npos) {
        std::size_t start = sp + SUBJ.size();
        std::size_t end = out.find('"', start);
        if (end != std::string::npos)
            out.replace(start, end - start, overridePatientId);
    }

    // Rewrite top-level "id":"<...>" with a sim-stable id (resource type +
    // patient + first 8 chars of original id). We do this only once, by
    // locating the first occurrence after the resourceType field.
    const std::string RT = "\"resourceType\":\"" + resourceType + "\"";
    std::size_t rt = out.find(RT);
    if (rt != std::string::npos) {
        std::size_t idPos = out.find("\"id\":\"", rt);
        if (idPos != std::string::npos) {
            std::size_t start = idPos + 6;
            std::size_t end = out.find('"', start);
            if (end != std::string::npos) {
                std::string newId = resourceType + "-" + overridePatientId;
                // Keep within reasonable bounds (don't blow up the JSON size).
                out.replace(start, end - start, newId);
            }
        }
    }
    return out;
}

std::string FhirCorpus::getResource(const std::string &resourceType,
                                    std::size_t index,
                                    const std::string &overridePatientId) const {
    auto it = resourcesByType.find(resourceType);
    if (it == resourcesByType.end() || it->second.empty())
        return "";
    const std::string &line = it->second[index % it->second.size()];
    return rewriteForPatient(line, resourceType, overridePatientId);
}

} // namespace ndnpreencryption
