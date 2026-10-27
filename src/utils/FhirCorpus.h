#ifndef __NDNPREENCRYPTION_FHIRCORPUS_H_
#define __NDNPREENCRYPTION_FHIRCORPUS_H_

#include <map>
#include <string>
#include <vector>
#include <cstddef>

namespace ndnpreencryption {

/**
 * Loads real Synthea-generated HL7 FHIR R5 bulk-export NDJSON resources from a
 * directory layout like:
 *   <root>/Patient.000.ndjson
 *   <root>/Observation.000.ndjson
 *   <root>/MedicationRequest.000.ndjson
 *   <root>/DiagnosticReport.000.ndjson
 *   <root>/Condition.000.ndjson
 *   <root>/Encounter.000.ndjson
 *   <root>/AllergyIntolerance.000.ndjson
 *   <root>/Procedure.000.ndjson
 *   <root>/Immunization.000.ndjson
 *   <root>/DocumentReference.000.ndjson
 *
 * Each NDJSON file is one FHIR resource per line. The corpus is loaded once
 * (per process) and resources are returned by deterministic index so repeat
 * Interests for the same content name always resolve to the same JSON body
 * (NDN data-immutability contract).
 *
 * If the directory is missing or empty for a given type, getResource() returns
 * "" so the caller can fall back to a synthesized resource.
 */
class FhirCorpus {
public:
    // Singleton accessor; safe to call from any module. The first caller
    // initializes from rootDir. Subsequent calls return the same instance
    // (rootDir is ignored after first load).
    static FhirCorpus &instance(const std::string &rootDir = "");

    // Returns the number of resources loaded for the given type.
    std::size_t countOf(const std::string &resourceType) const;

    // Returns one resource JSON line, picked deterministically using `index`.
    // If no resources are loaded for `resourceType`, returns "".
    // The returned JSON is the EXACT line from the NDJSON file, modulo a
    // single rewrite of "subject.reference" / "id" to incorporate the
    // simulation's patientId so traceability holds end-to-end.
    std::string getResource(const std::string &resourceType,
                            std::size_t index,
                            const std::string &overridePatientId = "") const;

    // True iff at least one resource type was loaded successfully.
    bool isLoaded() const { return loaded; }

    // For diagnostics.
    std::size_t totalLoaded() const;
    const std::string &rootDir() const { return root; }

    // Disable copy/move; singleton.
    FhirCorpus(const FhirCorpus &) = delete;
    FhirCorpus &operator=(const FhirCorpus &) = delete;

private:
    FhirCorpus() = default;

    void loadOnce(const std::string &rootDir);
    void loadOneType(const std::string &resourceType,
                     const std::string &path);

    std::map<std::string, std::vector<std::string>> resourcesByType;
    std::string root;
    bool loaded = false;
};

} // namespace ndnpreencryption

#endif
