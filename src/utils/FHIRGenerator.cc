#include "FHIRGenerator.h"
#include "Json.h"

#include <cstdio>
#include <random>
#include <vector>

namespace ndnpreencryption {

FHIRGenerator::FHIRGenerator() = default;

unsigned FHIRGenerator::seedFromName(const std::string &name) {
    // FNV-1a 32-bit, deterministic.
    unsigned h = 2166136261u;
    for (char c : name) {
        h ^= (unsigned char)c;
        h *= 16777619u;
    }
    return h;
}

std::string FHIRGenerator::resourceTypeFromName(const std::string &name) {
    // Names look like /hospitalX/<unit>/patient<id>/<Type>/<kind>/<version>
    // Pull the 4th '/' component.
    size_t pos = 0;
    int idx = 0;
    while (idx < 4 && pos < name.size()) {
        if (name[pos] == '/') idx++;
        if (idx == 4) break;
        pos++;
    }
    if (idx != 4 || pos >= name.size()) return "";
    pos++; // skip '/'
    size_t end = name.find('/', pos);
    if (end == std::string::npos) end = name.size();
    return name.substr(pos, end - pos);
}

std::string FHIRGenerator::sensitivityForResource(const std::string &type) {
    // Sensitivity bands derived from:
    //   Cobrado et al. 2024 "Access control solutions in EHR" (IMU)
    //   Atlam & Yang 2025 Future Internet 17(6):262 (RBAC+ABAC risk scoring)
    //   HL7 FHIR R5 confidentiality codes (v3 ConfidentialityClassification)
    // Low      = demographics & encounter metadata
    // Medium   = vitals, allergies, dispense records, services
    // High     = diagnoses, prescriptions, imaging, reports, procedures, care plans
    if (type == "Patient")             return "Low";
    if (type == "Encounter")           return "Low";
    if (type == "ServiceRequest")      return "Medium";
    if (type == "Observation")         return "Medium";
    if (type == "AllergyIntolerance")  return "Medium";
    if (type == "MedicationDispense")  return "Medium";
    if (type == "Condition")           return "High";
    if (type == "MedicationRequest")   return "High";
    if (type == "DiagnosticReport")    return "High";
    if (type == "ImagingStudy")        return "High";
    if (type == "Procedure")           return "High";
    if (type == "CarePlan")            return "High";
    if (type == "DocumentReference")   return "Medium";
    return "Low";
}

std::string FHIRGenerator::buildResource(const std::string &contentName) {
    std::string type = resourceTypeFromName(contentName);
    if (type.empty()) return "";

    // Patient ID extraction (between "patient" and the next '/').
    std::string patientId = "unknown";
    size_t pp = contentName.find("/patient");
    if (pp != std::string::npos) {
        size_t end = contentName.find('/', pp + 1);
        if (end == std::string::npos) end = contentName.size();
        patientId = contentName.substr(pp + 1, end - pp - 1);
    }

    // Kind subcomponent (5th '/' segment), e.g. vitalSigns / CTscan / discharge.
    std::string kind;
    size_t pos = 0;
    int idx = 0;
    while (idx < 5 && pos < contentName.size()) {
        if (contentName[pos] == '/') idx++;
        pos++;
    }
    if (idx == 5 && pos <= contentName.size()) {
        size_t end = contentName.find('/', pos);
        if (end == std::string::npos) end = contentName.size();
        kind = contentName.substr(pos, end - pos);
    }

    unsigned seed = seedFromName(contentName);
    generated++;

    // Prefer real Synthea records from the bound corpus when available. The
    // corpus is shared across all simulation nodes (singleton), so calls
    // for the same content name resolve to the same JSON line every time
    // (NDN data-immutability contract).
    if (corpus != nullptr && corpus->isLoaded()) {
        std::string fromReal = corpus->getResource(type, seed, patientId);
        if (!fromReal.empty()) {
            fromCorpus++;
            return fromReal;
        }
    }

    synthesized++;

    if (type == "Patient")            return buildPatient(patientId);
    if (type == "Observation")        return buildObservation(patientId, kind, seed);
    if (type == "MedicationRequest")  return buildMedicationRequest(patientId, seed);
    if (type == "DiagnosticReport")   return buildDiagnosticReport(patientId, kind, seed);
    if (type == "AllergyIntolerance") return buildAllergyIntolerance(patientId, seed);
    if (type == "Encounter")          return buildEncounter(patientId, seed);

    return "";
}

std::string FHIRGenerator::buildPatient(const std::string &patientId) {
    // ~2.0-2.5 KB Patient resource with realistic fields.
    Json::ObjectBuilder name;
    name.addArrayOfStrings("given", {"Alex", "M"})
        .addString("family", "Doe-" + patientId)
        .addString("use", "official");
    std::string nameArr = "[" + name.str() + "]";

    Json::ObjectBuilder addr;
    addr.addArrayOfStrings("line", {"123 Cedar Ave", "Apt 4B"})
        .addString("city", "Islamabad")
        .addString("state", "ICT")
        .addString("postalCode", "44000")
        .addString("country", "PK");
    std::string addrArr = "[" + addr.str() + "]";

    Json::ObjectBuilder contact;
    contact.addString("system", "phone")
           .addString("value", "+92-300-1234567")
           .addString("use", "mobile");
    Json::ObjectBuilder contact2;
    contact2.addString("system", "email")
            .addString("value", "alex.doe@example.com")
            .addString("use", "work");
    std::string telecomArr = "[" + contact.str() + "," + contact2.str() + "]";

    Json::ObjectBuilder identifier;
    identifier.addString("system", "http://hospitalX.example/mrn")
              .addString("value", "MRN-" + patientId)
              .addString("use", "usual");
    std::string identArr = "[" + identifier.str() + "]";

    Json::ObjectBuilder root;
    root.addString("resourceType", "Patient")
        .addString("id", patientId)
        .addRaw("meta",
                "{\"versionId\":\"1\",\"lastUpdated\":\"2026-05-01T08:00:00Z\","
                "\"profile\":[\"http://hl7.org/fhir/StructureDefinition/Patient\"]}")
        .addRaw("identifier", identArr)
        .addBool("active", true)
        .addRaw("name", nameArr)
        .addRaw("telecom", telecomArr)
        .addString("gender", "male")
        .addString("birthDate", "1985-04-12")
        .addRaw("address", addrArr)
        .addRaw("maritalStatus",
                "{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/v3-MaritalStatus\","
                "\"code\":\"M\",\"display\":\"Married\"}],\"text\":\"Married\"}")
        .addRaw("communication",
                "[{\"language\":{\"coding\":[{\"system\":\"urn:ietf:bcp:47\","
                "\"code\":\"en-US\",\"display\":\"English (United States)\"}]},\"preferred\":true}]");
    return root.str();
}

std::string FHIRGenerator::buildObservation(const std::string &patientId,
                                            const std::string &kind, unsigned seed) {
    std::mt19937 rng(seed);
    Json::ObjectBuilder root;
    root.addString("resourceType", "Observation")
        .addString("id", "obs-" + patientId + "-" + std::to_string(seed))
        .addString("status", "final");

    if (kind == "vitalSigns") {
        // 4-component vital signs panel (heart rate, SpO2, BP, temperature).
        std::string comps =
            "[{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"8867-4\",\"display\":\"Heart rate\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(60 + (rng() % 50)) +
            ",\"unit\":\"/min\",\"system\":\"http://unitsofmeasure.org\",\"code\":\"/min\"}},"
            "{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"59408-5\",\"display\":\"Oxygen saturation in Arterial blood by Pulse oximetry\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(92 + (rng() % 7)) +
            ",\"unit\":\"%\",\"system\":\"http://unitsofmeasure.org\",\"code\":\"%\"}},"
            "{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"8480-6\",\"display\":\"Systolic blood pressure\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(100 + (rng() % 50)) +
            ",\"unit\":\"mm[Hg]\",\"system\":\"http://unitsofmeasure.org\",\"code\":\"mm[Hg]\"}},"
            "{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"8310-5\",\"display\":\"Body temperature\"}]},"
            "\"valueQuantity\":{\"value\":36." + std::to_string(rng() % 9) +
            ",\"unit\":\"Cel\",\"system\":\"http://unitsofmeasure.org\",\"code\":\"Cel\"}}]";
        root.addRaw("category",
                    "[{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/observation-category\","
                    "\"code\":\"vital-signs\",\"display\":\"Vital Signs\"}]}]")
            .addRaw("code",
                    "{\"coding\":[{\"system\":\"http://loinc.org\","
                    "\"code\":\"85353-1\",\"display\":\"Vital signs, weight, height, head circumference panel\"}]}")
            .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
            .addString("effectiveDateTime", "2026-05-13T09:0" + std::to_string(rng() % 10) + ":00Z")
            .addRaw("component", comps);
    } else if (kind == "labResults" || kind == "bloodTest") {
        std::string comps =
            "[{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"6690-2\",\"display\":\"Leukocytes [#/volume] in Blood by Automated count\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(4 + (rng() % 8)) +
            ".0,\"unit\":\"10*3/uL\"}},"
            "{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"789-8\",\"display\":\"Erythrocytes [#/volume] in Blood by Automated count\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(4 + (rng() % 2)) +
            ".5,\"unit\":\"10*6/uL\"}},"
            "{\"code\":{\"coding\":[{\"system\":\"http://loinc.org\","
            "\"code\":\"2345-7\",\"display\":\"Glucose [Mass/volume] in Serum or Plasma\"}]},"
            "\"valueQuantity\":{\"value\":" + std::to_string(80 + (rng() % 60)) +
            ",\"unit\":\"mg/dL\"}}]";
        root.addRaw("category",
                    "[{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/observation-category\","
                    "\"code\":\"laboratory\",\"display\":\"Laboratory\"}]}]")
            .addRaw("code",
                    "{\"coding\":[{\"system\":\"http://loinc.org\","
                    "\"code\":\"58410-2\",\"display\":\"Complete blood count (hemogram) panel - Blood by Automated count\"}]}")
            .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
            .addString("effectiveDateTime", "2026-05-13T07:00:00Z")
            .addRaw("component", comps);
    } else {
        // Generic single-value observation.
        root.addRaw("code",
                    "{\"coding\":[{\"system\":\"http://loinc.org\","
                    "\"code\":\"8302-2\",\"display\":\"Body height\"}]}")
            .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
            .addString("effectiveDateTime", "2026-05-13T08:00:00Z")
            .addRaw("valueQuantity",
                    std::string("{\"value\":") + std::to_string(150 + (rng() % 50)) +
                    ",\"unit\":\"cm\"}");
    }
    return root.str();
}

std::string FHIRGenerator::buildMedicationRequest(const std::string &patientId,
                                                  unsigned seed) {
    std::mt19937 rng(seed);
    static const char *meds[] = {
        "Amoxicillin 500mg", "Metformin 1000mg", "Lisinopril 10mg",
        "Atorvastatin 20mg", "Levothyroxine 75mcg"
    };
    static const char *codes[] = {
        "723", "6809", "29046", "83367", "10582"
    };
    int mi = rng() % 5;

    Json::ObjectBuilder root;
    root.addString("resourceType", "MedicationRequest")
        .addString("id", "rx-" + patientId + "-" + std::to_string(seed))
        .addString("status", "active")
        .addString("intent", "order")
        .addRaw("medicationCodeableConcept",
                std::string("{\"coding\":[{\"system\":\"http://www.nlm.nih.gov/research/umls/rxnorm\","
                            "\"code\":\"") + codes[mi] + "\",\"display\":\"" + meds[mi] + "\"}],\"text\":\""
                            + meds[mi] + "\"}")
        .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
        .addString("authoredOn", "2026-05-13T10:30:00Z")
        .addRaw("requester",
                "{\"reference\":\"Practitioner/dr-house\",\"display\":\"Dr. Gregory House\"}")
        .addRaw("dosageInstruction",
                "[{\"sequence\":1,\"text\":\"Take 1 tablet by mouth twice daily\","
                "\"timing\":{\"repeat\":{\"frequency\":2,\"period\":1,\"periodUnit\":\"d\"}},"
                "\"route\":{\"coding\":[{\"system\":\"http://snomed.info/sct\","
                "\"code\":\"26643006\",\"display\":\"Oral route\"}]},"
                "\"doseAndRate\":[{\"doseQuantity\":{\"value\":1,\"unit\":\"tablet\"}}]}]")
        .addRaw("dispenseRequest",
                "{\"validityPeriod\":{\"start\":\"2026-05-13\",\"end\":\"2026-06-13\"},"
                "\"numberOfRepeatsAllowed\":2,"
                "\"quantity\":{\"value\":60,\"unit\":\"tablet\"},"
                "\"expectedSupplyDuration\":{\"value\":30,\"unit\":\"days\","
                "\"system\":\"http://unitsofmeasure.org\",\"code\":\"d\"}}");
    return root.str();
}

std::string FHIRGenerator::buildDiagnosticReport(const std::string &patientId,
                                                 const std::string &kind, unsigned seed) {
    std::mt19937 rng(seed);
    std::string code, display;
    if (kind == "CTscan") {
        code = "24560-2"; display = "CT Abdomen";
    } else if (kind == "MRI") {
        code = "24590-9"; display = "MRI Brain";
    } else {
        code = "11502-2"; display = "Laboratory report";
    }

    // Simulate an inline base64-encoded image attachment. We cap the size
    // at 8 KB so that after AES-GCM ciphertext + base64 inflation (~4/3) +
    // PRE wrap + signature, the resulting Data packet stays under UDP's
    // 65535-byte limit. Real clinical thumbnails are typically 2-10 KB;
    // full DICOM studies travel over DICOMweb / chunked TCP, not single
    // UDP datagrams.
    size_t mediaLen = 2000 + (rng() % 6000);
    std::string media;
    media.reserve(mediaLen);
    static const char *b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < mediaLen; i++)
        media.push_back(b64chars[rng() % 64]);

    Json::ObjectBuilder root;
    root.addString("resourceType", "DiagnosticReport")
        .addString("id", "rep-" + patientId + "-" + std::to_string(seed))
        .addString("status", "final")
        .addRaw("category",
                "[{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/v2-0074\","
                "\"code\":\"RAD\",\"display\":\"Radiology\"}]}]")
        .addRaw("code",
                std::string("{\"coding\":[{\"system\":\"http://loinc.org\","
                            "\"code\":\"") + code + "\",\"display\":\"" + display + "\"}],\"text\":\""
                            + display + "\"}")
        .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
        .addString("effectiveDateTime", "2026-05-13T11:00:00Z")
        .addString("issued", "2026-05-13T11:30:00Z")
        .addRaw("performer",
                "[{\"reference\":\"Practitioner/radiologist-1\","
                "\"display\":\"Dr. Cuddy\"}]")
        .addString("conclusion", "No acute abnormalities detected. Findings within normal limits.")
        .addRaw("presentedForm",
                std::string("[{\"contentType\":\"image/jpeg\","
                            "\"data\":\"") + media + "\","
                            "\"title\":\"" + display + "\"}]");
    return root.str();
}

std::string FHIRGenerator::buildAllergyIntolerance(const std::string &patientId,
                                                   unsigned seed) {
    std::mt19937 rng(seed);
    static const char *substances[] = {
        "Penicillin", "Sulfa drugs", "Latex", "Peanuts", "Shellfish"
    };
    static const char *codes[] = {
        "373270004", "294495009", "111088007", "256355007", "300913006"
    };
    int si = rng() % 5;

    Json::ObjectBuilder root;
    root.addString("resourceType", "AllergyIntolerance")
        .addString("id", "allergy-" + patientId + "-" + std::to_string(seed))
        .addRaw("clinicalStatus",
                "{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical\","
                "\"code\":\"active\",\"display\":\"Active\"}]}")
        .addRaw("verificationStatus",
                "{\"coding\":[{\"system\":\"http://terminology.hl7.org/CodeSystem/allergyintolerance-verification\","
                "\"code\":\"confirmed\",\"display\":\"Confirmed\"}]}")
        .addString("type", "allergy")
        .addRaw("category", "[\"medication\"]")
        .addString("criticality", "high")
        .addRaw("code",
                std::string("{\"coding\":[{\"system\":\"http://snomed.info/sct\","
                            "\"code\":\"") + codes[si] + "\",\"display\":\"" + substances[si] + "\"}],\"text\":\""
                            + substances[si] + "\"}")
        .addRaw("patient", "{\"reference\":\"Patient/" + patientId + "\"}")
        .addString("recordedDate", "2026-01-15");
    return root.str();
}

std::string FHIRGenerator::buildEncounter(const std::string &patientId, unsigned seed) {
    (void)seed;
    Json::ObjectBuilder root;
    root.addString("resourceType", "Encounter")
        .addString("id", "enc-" + patientId)
        .addString("status", "in-progress")
        .addRaw("class",
                "{\"system\":\"http://terminology.hl7.org/CodeSystem/v3-ActCode\","
                "\"code\":\"IMP\",\"display\":\"inpatient encounter\"}")
        .addRaw("subject", "{\"reference\":\"Patient/" + patientId + "\"}")
        .addRaw("period",
                "{\"start\":\"2026-05-13T08:00:00Z\"}")
        .addRaw("serviceProvider",
                "{\"reference\":\"Organization/hospitalX\",\"display\":\"Hospital X\"}");
    return root.str();
}

std::vector<std::string> FHIRGenerator::buildCatalog(int size,
                                                     const std::string &orgPrefix) {
    // Catalog units match the consumer taxonomy used by the didvc scenarios
    // (8 clinical roles across 7 units + 2 administrative roles). Including
    // Pharmacy/Oncology/Surgery here is what allows Pharmacists, Oncology
    // attendings, and Surgeons to find role-aligned content in their
    // preferred subset — see Consumer::initialize().
    static const char *units[] = {"ICU", "Emergency", "Radiology", "Pharmacy",
                                  "Oncology", "Surgery", "Reception",
                                  "Administration", "ClinicA"};
    static const char *types[] = {"Observation", "Patient", "MedicationRequest",
                                  "MedicationDispense", "DiagnosticReport",
                                  "ImagingStudy", "AllergyIntolerance",
                                  "Encounter", "Procedure", "Condition",
                                  "CarePlan"};
    static const char *kinds[] = {"vitalSigns", "labResults", "demographics",
                                  "CTscan", "MRI", "bloodTest", "discharge",
                                  "intake", "consult"};
    const int nUnits = sizeof(units)/sizeof(units[0]);
    const int nTypes = sizeof(types)/sizeof(types[0]);
    const int nKinds = sizeof(kinds)/sizeof(kinds[0]);
    std::vector<std::string> cat;
    cat.reserve(size);
    // Unit, resource type and kind are drawn from independent strides of i
    // so that every unit holds every resource type (no aliasing between the
    // 9 units and the 9 kinds), and patients are spread over 500 ids.
    for (int i = 0; i < size; i++) {
        const char *unit = units[i % nUnits];
        const char *type = types[(i / nUnits) % nTypes];
        const char *kind = kinds[(i / (nUnits * nTypes)) % nKinds];
        char buf[160];
        std::snprintf(buf, sizeof(buf), "%s/%s/patient%d/%s/%s/v%d",
                      orgPrefix.c_str(), unit,
                      100 + (i * 7) % 500, type, kind, 1 + (i / 99) % 50);
        cat.emplace_back(buf);
    }
    return cat;
}

} // namespace ndnpreencryption
