#ifndef __NDNPREENCRYPTION_FHIRGENERATOR_H_
#define __NDNPREENCRYPTION_FHIRGENERATOR_H_

#include "FhirCorpus.h"

#include <map>
#include <string>
#include <vector>

namespace ndnpreencryption {

/**
 * Generates HL7 FHIR R5 JSON resource bodies for use as NDN Data payloads.
 *
 * Realistic, not random: every byte returned is structured FHIR JSON with
 * LOINC/SNOMED codes appropriate to the resource type. The Data packet's
 * byteLength is set from the actual serialised size, so radio metrics
 * downstream reflect what real EHR traffic looks like (Observation ~1.2 KB,
 * Patient ~2.5 KB, MedicationRequest ~2 KB, DiagnosticReport with attached
 * Media ~5–50 KB).
 *
 * Resource selection is deterministic in the content name: the generator
 * derives a stable seed from the patient ID + resource type so repeat
 * Interests for the same name yield identical payloads (matching NDN's
 * data-immutability contract and letting Routers cache hits make sense).
 */
class FHIRGenerator {
public:
    FHIRGenerator();

    // Look up FHIR resource body for an NDN content name like
    //   /hospitalX/ICU/patient42/Observation/vitalSigns/v17
    // Returns "" if the type is not recognised.
    std::string buildResource(const std::string &contentName);

    // Classify a content name into its FHIR resource type (used by callers
    // that want to size or route based on type).
    static std::string resourceTypeFromName(const std::string &contentName);

    // Pre-computed catalog of well-formed content names for Consumer init.
    // Each name maps to a deterministic FHIR resource so different runs are
    // reproducible.
    std::vector<std::string> buildCatalog(int size,
                                          const std::string &organizationPrefix);

    // Sensitivity classification derived from FHIR resource type. Used by
    // Consumer to set the legacy sensitivityLevel field on Interest packets.
    static std::string sensitivityForResource(const std::string &fhirType);

    // Counter of resources successfully generated (for diagnostics).
    long resourcesGenerated() const { return generated; }
    long resourcesFromCorpus() const { return fromCorpus; }
    long resourcesSynthesized() const { return synthesized; }

    // Bind an external real-data corpus. When set (non-null) and the corpus
    // has a matching resource type loaded, buildResource() prefers the real
    // Synthea record over the synthesized one. Falls back automatically.
    void useCorpus(FhirCorpus *c) { corpus = c; }

private:
    long generated = 0;
    long fromCorpus = 0;
    long synthesized = 0;
    FhirCorpus *corpus = nullptr;

    // Per-resource builders. Each returns canonical JSON.
    std::string buildPatient(const std::string &patientId);
    std::string buildObservation(const std::string &patientId,
                                 const std::string &observationKind,
                                 unsigned seed);
    std::string buildMedicationRequest(const std::string &patientId,
                                       unsigned seed);
    std::string buildDiagnosticReport(const std::string &patientId,
                                      const std::string &kind, unsigned seed);
    std::string buildAllergyIntolerance(const std::string &patientId,
                                        unsigned seed);
    std::string buildEncounter(const std::string &patientId, unsigned seed);

    // Deterministic seed derived from contentName.
    static unsigned seedFromName(const std::string &name);
};

} // namespace ndnpreencryption

#endif
