#include "Json.h"

#include <cstdio>
#include <sstream>

namespace ndnpreencryption {
namespace Json {

std::string escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
    return out;
}

ObjectBuilder& ObjectBuilder::addString(const std::string &key, const std::string &value) {
    entries.emplace_back(key, escape(value));
    return *this;
}
ObjectBuilder& ObjectBuilder::addRawString(const std::string &key, const std::string &value) {
    entries.emplace_back(key, value);
    return *this;
}
ObjectBuilder& ObjectBuilder::addInt(const std::string &key, long long value) {
    entries.emplace_back(key, std::to_string(value));
    return *this;
}
ObjectBuilder& ObjectBuilder::addDouble(const std::string &key, double value) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.6f", value);
    entries.emplace_back(key, buf);
    return *this;
}
ObjectBuilder& ObjectBuilder::addBool(const std::string &key, bool value) {
    entries.emplace_back(key, value ? "true" : "false");
    return *this;
}
ObjectBuilder& ObjectBuilder::addArrayOfStrings(const std::string &key,
                                                 const std::vector<std::string> &values) {
    std::string arr = "[";
    for (size_t i = 0; i < values.size(); i++) {
        if (i) arr.push_back(',');
        arr += escape(values[i]);
    }
    arr.push_back(']');
    entries.emplace_back(key, arr);
    return *this;
}
ObjectBuilder& ObjectBuilder::addRaw(const std::string &key, const std::string &rawJson) {
    entries.emplace_back(key, rawJson);
    return *this;
}
std::string ObjectBuilder::str() const {
    std::string out = "{";
    for (size_t i = 0; i < entries.size(); i++) {
        if (i) out.push_back(',');
        out += escape(entries[i].first);
        out.push_back(':');
        out += entries[i].second;
    }
    out.push_back('}');
    return out;
}

namespace {
// Find the first unescaped occurrence of `"<key>"` followed by ':' (allowing
// whitespace). Returns the position of the value start, or std::string::npos.
size_t findKey(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(needle, pos);
        if (pos == std::string::npos) return pos;
        size_t after = pos + needle.size();
        while (after < json.size() && (json[after] == ' ' || json[after] == '\t')) after++;
        if (after < json.size() && json[after] == ':') {
            after++;
            while (after < json.size() && (json[after] == ' ' || json[after] == '\t')) after++;
            return after;
        }
        pos = after;
    }
}

// Read a JSON string starting at `pos` (must point at opening quote). Returns
// the decoded string and updates `pos` past the closing quote.
std::string readString(const std::string &json, size_t &pos) {
    std::string out;
    if (pos >= json.size() || json[pos] != '"') return out;
    pos++;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            char c = json[pos + 1];
            switch (c) {
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case '\\': out.push_back('\\'); break;
                case '"': out.push_back('"'); break;
                default: out.push_back(c); break;
            }
            pos += 2;
        } else {
            out.push_back(json[pos++]);
        }
    }
    if (pos < json.size()) pos++; // consume closing quote
    return out;
}
} // namespace

std::string extractString(const std::string &json, const std::string &key) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos) return "";
    if (pos >= json.size() || json[pos] != '"') return "";
    return readString(json, pos);
}

long long extractInt(const std::string &json, const std::string &key, long long defaultValue) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos) return defaultValue;
    // Read decimal integer.
    long long sign = 1;
    if (pos < json.size() && json[pos] == '-') { sign = -1; pos++; }
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos])))
        return defaultValue;
    long long v = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
        v = v * 10 + (json[pos] - '0');
        pos++;
    }
    return sign * v;
}

double extractDouble(const std::string &json, const std::string &key, double defaultValue) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos) return defaultValue;
    char buf[64];
    size_t i = 0;
    while (pos < json.size() && i + 1 < sizeof(buf)) {
        char c = json[pos];
        if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
            break;
        buf[i++] = c;
        pos++;
    }
    buf[i] = '\0';
    if (i == 0) return defaultValue;
    return std::strtod(buf, nullptr);
}

bool extractBool(const std::string &json, const std::string &key, bool defaultValue) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos) return defaultValue;
    if (json.compare(pos, 4, "true") == 0) return true;
    if (json.compare(pos, 5, "false") == 0) return false;
    return defaultValue;
}

std::string extractObject(const std::string &json, const std::string &key) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos || pos >= json.size() || json[pos] != '{') return "";
    int depth = 0;
    size_t start = pos;
    bool inStr = false;
    while (pos < json.size()) {
        char c = json[pos];
        if (inStr) {
            if (c == '\\' && pos + 1 < json.size()) { pos += 2; continue; }
            if (c == '"') inStr = false;
        } else {
            if (c == '"') inStr = true;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return json.substr(start, pos - start + 1);
                }
            }
        }
        pos++;
    }
    return "";
}

std::string extractArray(const std::string &json, const std::string &key) {
    size_t pos = findKey(json, key);
    if (pos == std::string::npos || pos >= json.size() || json[pos] != '[') return "";
    int depth = 0;
    size_t start = pos;
    bool inStr = false;
    while (pos < json.size()) {
        char c = json[pos];
        if (inStr) {
            if (c == '\\' && pos + 1 < json.size()) { pos += 2; continue; }
            if (c == '"') inStr = false;
        } else {
            if (c == '"') inStr = true;
            else if (c == '[') depth++;
            else if (c == ']') {
                depth--;
                if (depth == 0) {
                    return json.substr(start, pos - start + 1);
                }
            }
        }
        pos++;
    }
    return "";
}

std::vector<std::string> splitArrayElements(const std::string &rawArray) {
    std::vector<std::string> out;
    if (rawArray.size() < 2 || rawArray.front() != '[' || rawArray.back() != ']')
        return out;
    size_t i = 1, n = rawArray.size() - 1;
    while (i < n) {
        while (i < n && (rawArray[i] == ' ' || rawArray[i] == ',' ||
                         rawArray[i] == '\n' || rawArray[i] == '\t' || rawArray[i] == '\r'))
            i++;
        if (i >= n) break;
        size_t start = i;
        char c = rawArray[i];
        if (c == '{' || c == '[') {
            char open = c, close = (c == '{') ? '}' : ']';
            int depth = 0;
            bool inStr = false;
            while (i < n) {
                char d = rawArray[i];
                if (inStr) {
                    if (d == '\\' && i + 1 < n) { i += 2; continue; }
                    if (d == '"') inStr = false;
                } else {
                    if (d == '"') inStr = true;
                    else if (d == open) depth++;
                    else if (d == close) { depth--; if (depth == 0) { i++; break; } }
                }
                i++;
            }
            out.emplace_back(rawArray.substr(start, i - start));
        } else if (c == '"') {
            i++;
            while (i < n && rawArray[i] != '"') {
                if (rawArray[i] == '\\' && i + 1 < n) i += 2;
                else i++;
            }
            if (i < n) i++; // closing quote
            out.emplace_back(rawArray.substr(start, i - start));
        } else {
            while (i < n && rawArray[i] != ',') i++;
            out.emplace_back(rawArray.substr(start, i - start));
        }
    }
    return out;
}

} // namespace Json
} // namespace ndnpreencryption
