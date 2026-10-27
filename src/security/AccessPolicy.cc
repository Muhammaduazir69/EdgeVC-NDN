#include "AccessPolicy.h"

#include <vector>

namespace ndnpreencryption {

namespace {
std::vector<std::string> splitName(const std::string &name) {
    std::vector<std::string> parts;
    size_t i = 0;
    while (i < name.size()) {
        if (name[i] == '/') { i++; continue; }
        size_t j = name.find('/', i);
        if (j == std::string::npos) j = name.size();
        parts.push_back(name.substr(i, j - i));
        i = j;
    }
    return parts;
}
} // namespace

ResourceAttrs ResourceAttrs::fromName(const std::string &name) {
    ResourceAttrs r;
    auto p = splitName(name);
    if (p.size() < 4) return r;
    r.unit = p[1];
    r.type = p[3];
    r.sensitivity = AccessPolicy::sensitivityForType(r.type);
    r.valid = true;
    return r;
}

std::string AccessPolicy::sensitivityForType(const std::string &t) {
    // HL7 v3 confidentiality bands as commonly applied to FHIR resources:
    // demographics/encounters low, vitals/allergies/dispense moderate,
    // diagnoses/orders/imaging/reports/procedures/care plans high.
    if (t == "Patient" || t == "Encounter") return "Low";
    if (t == "Observation" || t == "AllergyIntolerance" ||
        t == "MedicationDispense" || t == "DocumentReference") return "Medium";
    if (t == "Condition" || t == "MedicationRequest" || t == "DiagnosticReport" ||
        t == "ImagingStudy" || t == "Procedure" || t == "CarePlan") return "High";
    return "High";
}

int AccessPolicy::clearanceNeeded(const std::string &s) {
    if (s == "Low") return 1;
    if (s == "Medium") return 2;
    return 3;
}

bool AccessPolicy::isClinicalRole(const std::string &r) {
    return r == "Attending" || r == "Resident" || r == "Nurse" || r == "Surgeon" ||
           r == "Anesthesiologist" || r == "Radiologist" || r == "Doctor";
}

std::string AccessPolicy::evaluate(const SubjectAttrs &s, const ResourceAttrs &r,
                                   bool breakGlass) {
    if (!r.valid) return "";
    const bool sameUnit = (s.unit == r.unit);
    if (isClinicalRole(s.role) && sameUnit &&
        s.clearance >= clearanceNeeded(r.sensitivity))
        return "P1";
    if (s.role == "LabTechnician" && sameUnit &&
        (r.sensitivity == "Low" || r.sensitivity == "Medium"))
        return "P2";
    if (s.role == "Pharmacist" && s.clearance >= 3 &&
        (r.type == "MedicationRequest" || r.type == "MedicationDispense" ||
         r.type == "AllergyIntolerance" || r.type == "Patient"))
        return "P3";
    if ((s.role == "Receptionist" || s.role == "Administrator") &&
        (r.type == "Patient" || r.type == "Encounter"))
        return "P4";
    if (s.role == "Attending" && (s.unit == "ICU" || s.unit == "Emergency") &&
        (r.sensitivity == "Low" || r.sensitivity == "Medium"))
        return "P5";
    if (breakGlass && isClinicalRole(s.role) && s.clearance >= 3)
        return "BG";
    return "";
}

} // namespace ndnpreencryption
