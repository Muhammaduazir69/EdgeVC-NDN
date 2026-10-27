#ifndef __NDNPREENCRYPTION_ACCESSPOLICY_H_
#define __NDNPREENCRYPTION_ACCESSPOLICY_H_

#include <string>

namespace ndnpreencryption {

struct SubjectAttrs {
    std::string role;
    std::string unit;
    int clearance = 1;
};

// Attributes of a resource are read from its NDN name, never from fields the
// requester controls:  /<org>/<unit>/patient<id>/<FHIRType>/<kind>/v<k>
struct ResourceAttrs {
    std::string unit;
    std::string type;
    std::string sensitivity;   // Low | Medium | High (from the FHIR type)
    bool valid = false;
    static ResourceAttrs fromName(const std::string &name);
};

/**
 * One policy, shared by every framework (the comparison changes where and
 * how it is evaluated, never what it says). Rules, first match wins:
 *   P1 in-unit clinical    clinical role, same unit, clearance >= need(s)
 *   P2 laboratory          LabTechnician, same unit, s in {Low, Medium}
 *   P3 pharmacy            Pharmacist, clearance >= 3, medication/allergy/
 *                          demographic resources in any unit
 *   P4 front office        Receptionist/Administrator, Patient/Encounter
 *   P5 acute consult       ICU/Emergency Attending, s <= Medium, any unit
 *   BG break-glass         clinical role, clearance >= 3, flagged request
 * need(Low)=1, need(Medium)=2, need(High)=3.
 */
class AccessPolicy {
  public:
    // Returns the matching rule ("P1".."P5","BG") or "" when denied.
    static std::string evaluate(const SubjectAttrs &s, const ResourceAttrs &r,
                                bool breakGlass);
    static bool isClinicalRole(const std::string &role);
    static std::string sensitivityForType(const std::string &type);
    static int clearanceNeeded(const std::string &sensitivity);
};

} // namespace ndnpreencryption

#endif
