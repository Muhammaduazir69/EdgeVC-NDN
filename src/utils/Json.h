#ifndef __NDNPREENCRYPTION_JSON_H_
#define __NDNPREENCRYPTION_JSON_H_

#include <string>
#include <vector>
#include <cstdint>

namespace ndnpreencryption {

// Minimal canonical JSON helper used by DID/VC/VCList for signing payloads.
// We intentionally avoid pulling in a full third-party JSON library — the
// schemas in this project are fixed and small, so a focused string-based
// builder + field extractor is enough.
//
// Canonical rules:
//  * keys are emitted in the order they were inserted (the *caller* is
//    responsible for inserting in sorted order if canonicalisation is needed)
//  * no whitespace between tokens
//  * strings are JSON-escaped (RFC 8259 minimal: \" \\ \n \r \t)
//  * numbers are emitted as plain decimal, no scientific notation
namespace Json {

std::string escape(const std::string &s);

// Builders --------------------------------------------------------------
class ObjectBuilder {
public:
    ObjectBuilder& addString(const std::string &key, const std::string &value);
    ObjectBuilder& addRawString(const std::string &key, const std::string &value); // value already escaped/quoted
    ObjectBuilder& addInt(const std::string &key, long long value);
    ObjectBuilder& addDouble(const std::string &key, double value);
    ObjectBuilder& addBool(const std::string &key, bool value);
    ObjectBuilder& addArrayOfStrings(const std::string &key, const std::vector<std::string> &values);
    ObjectBuilder& addRaw(const std::string &key, const std::string &rawJson); // raw object/array
    std::string str() const;
private:
    std::vector<std::pair<std::string,std::string>> entries; // (key, raw-value)
};

// Extractors (best-effort, schema-aware) -------------------------------
// Returns "" if not found / not a string. The needle is `"key":`.
std::string extractString(const std::string &json, const std::string &key);
long long   extractInt(const std::string &json, const std::string &key, long long defaultValue = 0);
double      extractDouble(const std::string &json, const std::string &key, double defaultValue = 0.0);
bool        extractBool(const std::string &json, const std::string &key, bool defaultValue = false);

// Extract a nested JSON object as a raw string (the opening { to its
// matching }). Returns "" if not found.
std::string extractObject(const std::string &json, const std::string &key);

// Extract an array as a raw string.
std::string extractArray(const std::string &json, const std::string &key);

// Split a raw JSON array string into element raw-strings.
std::vector<std::string> splitArrayElements(const std::string &rawArray);

} // namespace Json
} // namespace ndnpreencryption

#endif
