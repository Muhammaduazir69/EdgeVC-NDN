#include "MetricsCollector.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>

namespace ndnpreencryption {

MetricsCollector *MetricsCollector::inst = nullptr;

const char *byteClassName(ByteClass c) {
    switch (c) {
        case ByteClass::INTEREST_BASE: return "interest_base";
        case ByteClass::INTEREST_AUTH: return "interest_auth";
        case ByteClass::INTEREST_CREDENTIAL: return "interest_credential";
        case ByteClass::DATA: return "data";
        case ByteClass::DATA_PROTECTION: return "data_protection";
        case ByteClass::NACK: return "nack";
        case ByteClass::AUTHZ: return "authz";
        case ByteClass::ENDORSE: return "endorse";
        case ByteClass::VC_ISSUE: return "vc_issue";
        case ByteClass::IDENTITY_UPDATE: return "identity_update";
        case ByteClass::STATUS_DELTA: return "status_delta";
        case ByteClass::STATUS_SNAPSHOT: return "status_snapshot";
        case ByteClass::STATUS_SYNC: return "status_sync";
        case ByteClass::AUDIT: return "audit";
        default: return "?";
    }
}

MetricsCollector *MetricsCollector::getInstance() {
    if (!inst) inst = new MetricsCollector();
    return inst;
}

void MetricsCollector::reset(const std::string &fw, double wu) {
    *this = MetricsCollector();
    framework = fw;
    warmup = wu;
}

long MetricsCollector::newInterest(const InterestRecord &r) {
    InterestRecord c = r;
    c.id = (long)interests.size();
    interests.push_back(c);
    return c.id;
}

void MetricsCollector::interestOutcome(long id, int outcome, int nackReason, double tResp,
                                       bool decryptOk, int plainBytes) {
    if (id < 0 || id >= (long)interests.size()) return;
    InterestRecord &r = interests[id];
    if (r.outcome != -1) return;
    r.outcome = outcome;
    r.nackReason = nackReason;
    r.tResp = tResp;
    r.decryptOk = decryptOk;
    r.plainBytes = plainBytes;
}

void MetricsCollector::recordDecision(const DecisionRecord &d0) {
    DecisionRecord d = d0;
    if (d.verdict == 0 && !d.attack) {
        auto it = lifecycleByRequester.find(d.requester);
        if (it != lifecycleByRequester.end()) {
            for (auto &iv : it->second) {
                if (d.t >= iv.tStart && (iv.tEnd < 0 || d.t < iv.tEnd)) {
                    d.staleGrant = true;
                    iv.staleGrants++;
                    iv.lastStale = d.t;
                }
            }
        }
    }
    decisions.push_back(d);
}

void MetricsCollector::recordTx(ByteClass c, long bytes) {
    if (simTime().dbl() < warmup) return;
    linkBytes[(int)c] += bytes;
    linkPkts[(int)c]++;
}

void MetricsCollector::recordServiceBusy(int node, double busy, long served) {
    auto &e = serviceLoad[node];
    e.first += busy;
    e.second += served;
}

void MetricsCollector::lifecycle(const std::string &req, int idx, int st, double t) {
    auto &v = lifecycleByRequester[req];
    for (auto &iv : v)
        if (iv.tEnd < 0) iv.tEnd = t;
    if (st != 0) v.push_back({idx, st, t, -1.0, -1.0, 0});
}

bool MetricsCollector::isAuthoritativelyActive(const std::string &req) const {
    auto it = lifecycleByRequester.find(req);
    if (it == lifecycleByRequester.end()) return true;
    for (const auto &iv : it->second)
        if (iv.tEnd < 0) return false;
    return true;
}

void MetricsCollector::stateApplied(int node, long v, double t) {
    auto &m = applyTime[v];
    if (!m.count(node)) m[node] = t;
}

void MetricsCollector::statePublished(long v, double t, const std::string &kind) {
    publishTime[v] = t;
    publishKind[v] = kind;
}

namespace {
double pct(std::vector<double> v, double p) {
    if (v.empty()) return NAN;
    std::sort(v.begin(), v.end());
    double idx = p * (v.size() - 1);
    size_t lo = (size_t)std::floor(idx), hi = (size_t)std::ceil(idx);
    return v[lo] + (v[hi] - v[lo]) * (idx - lo);
}
double mean(const std::vector<double> &v) {
    if (v.empty()) return NAN;
    double s = 0;
    for (double x : v) s += x;
    return s / v.size();
}
std::string csv(const std::string &s) {
    if (s.find_first_of(",\"\n") == std::string::npos) return s;
    std::string o = "\"";
    for (char c : s) { if (c == '"') o += '"'; o += c; }
    return o + "\"";
}
} // namespace

void MetricsCollector::exportAll(const std::string &prefix, bool detailed) {
    double tEnd = simTime().dbl();
    double window = std::max(1e-9, tEnd - warmup);

    // Authoritative status of a holder at time t (inactive inside a
    // revocation or suspension interval).
    auto inactiveAt = [&](const std::string &req, double t) {
        auto it = lifecycleByRequester.find(req);
        if (it == lifecycleByRequester.end()) return false;
        for (const auto &iv : it->second)
            if (t >= iv.tStart && (iv.tEnd < 0 || t < iv.tEnd)) return true;
        return false;
    };
    // A request whose holder changed status between sending and being
    // answered (or timing out) has no unambiguous ground truth: the
    // decision may legitimately follow either status. Such transition
    // requests are counted but excluded from ASR, ADA and exposure, and so
    // are requests still pending when the run ends.
    std::vector<char> usable(interests.size(), 0);
    long transitional = 0;
    for (size_t k = 0; k < interests.size(); k++) {
        const auto &r = interests[k];
        if (r.tSend < warmup || r.outcome == -1) continue;
        if (!r.attack && !r.requester.empty() &&
            inactiveAt(r.requester, r.tSend) != inactiveAt(r.requester, r.tResp)) {
            transitional++;
            continue;
        }
        usable[k] = 1;
    }

    long nLegit = 0, nIllegit = 0, tp = 0, fn = 0, tn = 0, fp = 0;
    long nData = 0, nNack = 0, nTimeout = 0, nPending = 0;
    long legitNack = 0, legitTimeout = 0, attackN = 0, attackDelivered = 0;
    long bgN = 0, bgOk = 0, bgScopeN = 0, bgScopeOk = 0, bgUnqN = 0, bgUnqDenied = 0;
    std::vector<double> rttBgScope;
    double plainDelivered = 0;
    std::vector<double> rttLegit, rttBg, rttNormal;
    for (size_t k = 0; k < interests.size(); k++) {
        const auto &r = interests[k];
        if (r.tSend < warmup) continue;
        if (r.outcome == -1) { nPending++; continue; }
        if (!usable[k]) continue;
        if (r.outcome == 0) nData++;
        else if (r.outcome == 1) nNack++;
        else if (r.outcome == 2) nTimeout++;
        bool delivered = (r.outcome == 0 && r.decryptOk);
        if (r.attack) {
            attackN++;
            if (delivered) attackDelivered++;
            continue;
        }
        // Break-glass success is measured over flagged requests that the
        // emergency rule permits (and whose holder is active).
        if (r.breakGlass && r.expected) { bgN++; if (delivered) { bgOk++; rttBg.push_back(r.tResp - r.tSend); } }
        if (r.bgScope) { bgScopeN++; if (delivered) { bgScopeOk++; rttBgScope.push_back(r.tResp - r.tSend); } }
        if (r.bgUnqualified) { bgUnqN++; if (!delivered) bgUnqDenied++; }
        if (r.expected) {
            nLegit++;
            if (delivered) {
                tp++;
                rttLegit.push_back(r.tResp - r.tSend);
                if (!r.breakGlass) rttNormal.push_back(r.tResp - r.tSend);
                plainDelivered += r.plainBytes;
            } else {
                fn++;
                if (r.outcome == 1) legitNack++;
                else if (r.outcome == 2) legitTimeout++;
            }
        } else {
            nIllegit++;
            if (delivered) fp++; else tn++;
        }
    }

    // End-to-end exposure, observed at the consumer: plaintext delivered to a
    // holder whose credential was authoritatively revoked or suspended when
    // the Interest was sent, regardless of which node served it.
    long inactiveSent = 0, inactiveDelivered = 0;
    std::map<std::string, std::vector<double>> inactiveDeliveryTimes;
    for (size_t k = 0; k < interests.size(); k++) {
        const auto &r = interests[k];
        if (!usable[k] || r.attack || r.holderActive) continue;
        inactiveSent++;
        if (r.outcome == 0 && r.decryptOk) {
            inactiveDelivered++;
            inactiveDeliveryTimes[r.requester].push_back(r.tSend);
        }
    }
    std::vector<double> e2eExposure;
    for (const auto &kv : lifecycleByRequester)
        for (const auto &iv : kv.second) {
            if (iv.tStart < warmup) continue;
            double last = -1;
            auto it = inactiveDeliveryTimes.find(kv.first);
            if (it != inactiveDeliveryTimes.end())
                for (double t : it->second)
                    if (t >= iv.tStart && (iv.tEnd < 0 || t < iv.tEnd)) last = std::max(last, t);
            e2eExposure.push_back(last < 0 ? 0.0 : last - iv.tStart);
        }

    std::vector<double> dDelay, dDelayGrant, dCpu, dMeas;
    long grants = 0, staleGrants = 0, edgeCsGrantHits = 0;
    for (const auto &d : decisions) {
        if (d.t < warmup) continue;
        dDelay.push_back(d.decisionDelay);
        dCpu.push_back(d.modeledCpu);
        dMeas.push_back(d.measuredCpu);
        if (d.verdict == 0) {
            grants++;
            dDelayGrant.push_back(d.decisionDelay);
            if (d.csHit) edgeCsGrantHits++;
            if (d.staleGrant) staleGrants++;
        }
    }

    // Revocation exposure and state propagation.
    std::vector<double> exposure, exposureRevoke;
    long intervals = 0, intervalsWithStale = 0;
    for (const auto &kv : lifecycleByRequester)
        for (const auto &iv : kv.second) {
            if (iv.tStart < warmup) continue;
            intervals++;
            double e = iv.staleGrants > 0 ? iv.lastStale - iv.tStart : 0.0;
            exposure.push_back(e);
            if (iv.status == 1) exposureRevoke.push_back(e);
            if (iv.staleGrants > 0) intervalsWithStale++;
        }
    std::vector<double> applyLat, convergence;
    for (const auto &kv : applyTime) {
        auto pt = publishTime.find(kv.first);
        if (pt == publishTime.end() || pt->second < warmup) continue;
        double worst = 0;
        for (const auto &nv : kv.second) {
            double l = nv.second - pt->second;
            applyLat.push_back(l);
            worst = std::max(worst, l);
        }
        convergence.push_back(worst);
    }

    long totalBytes = 0;
    for (int i = 0; i < (int)ByteClass::COUNT; i++) totalBytes += linkBytes[i];
    long protBytes = linkBytes[(int)ByteClass::DATA_PROTECTION];
    long acBytes = totalBytes - linkBytes[(int)ByteClass::INTEREST_BASE] - linkBytes[(int)ByteClass::DATA] - protBytes;
    long nInterestsSent = 0;
    for (const auto &r : interests) if (r.tSend >= warmup) nInterestsSent++;

    double busyMax = 0;
    long served = 0;
    for (const auto &kv : serviceLoad) { busyMax = std::max(busyMax, kv.second.first); served += kv.second.second; }

    std::ofstream s(prefix + "_summary.csv");
    std::vector<std::pair<std::string, std::string>> row;
    auto add = [&](const std::string &k, double v) {
        std::ostringstream o;
        o.precision(9);
        o << v;
        row.emplace_back(k, o.str());
    };
    for (const auto &kv : meta) row.emplace_back(kv.first, kv.second);
    row.emplace_back("framework", framework);
    add("warmup", warmup);
    add("t_end", tEnd);
    add("interests", (double)(nData + nNack + nTimeout + nPending + transitional));
    add("legit", nLegit);
    add("illegit", nIllegit);
    add("tp", tp); add("fn", fn); add("tn", tn); add("fp", fp);
    add("asr", nLegit ? (double)tp / nLegit : NAN);
    add("ada", nIllegit ? (double)tn / nIllegit : NAN);
    add("legit_nack_rate", nLegit ? (double)legitNack / nLegit : NAN);
    add("legit_timeout_rate", nLegit ? (double)legitTimeout / nLegit : NAN);
    add("data", nData); add("nack", nNack); add("timeout", nTimeout); add("pending", nPending);
    add("transitional", transitional);
    add("latency_mean", mean(rttLegit));
    add("latency_p50", pct(rttLegit, 0.50));
    add("latency_p90", pct(rttLegit, 0.90));
    add("latency_p95", pct(rttLegit, 0.95));
    add("latency_p99", pct(rttLegit, 0.99));
    add("latency_normal_mean", mean(rttNormal));
    add("breakglass_n", bgN);
    add("breakglass_ok", bgOk);
    add("breakglass_latency_mean", mean(rttBg));
    add("breakglass_latency_p95", pct(rttBg, 0.95));
    add("breakglass_scope_n", bgScopeN);
    add("breakglass_scope_ok", bgScopeOk);
    add("breakglass_scope_latency_mean", mean(rttBgScope));
    add("breakglass_scope_latency_p95", pct(rttBgScope, 0.95));
    add("breakglass_unqualified_n", bgUnqN);
    add("breakglass_unqualified_denied", bgUnqDenied);
    add("audits_rejected", auditsRejected);
    add("audits_sent", auditsSent);
    add("audits_received", auditsRecv);
    add("audit_latency_mean", mean(auditLatency));
    add("goodput_Bps", plainDelivered / window);
    add("satisfied_per_s", tp / window);
    add("decision_delay_mean", mean(dDelay));
    add("decision_delay_grant_mean", mean(dDelayGrant));
    add("decision_delay_p95", pct(dDelay, 0.95));
    add("decision_cpu_modeled_mean", mean(dCpu));
    add("decision_cpu_measured_mean", mean(dMeas));
    add("decisions", (double)dDelay.size());
    add("grants", grants);
    add("stale_grants", staleGrants);
    add("edge_cs_hit_ratio", (edgeCsHits + edgeCsMisses) ? (double)edgeCsHits / (edgeCsHits + edgeCsMisses) : NAN);
    add("transit_cs_hit_ratio", (transitCsHits + transitCsMisses) ? (double)transitCsHits / (transitCsHits + transitCsMisses) : NAN);
    add("decision_cache_hit_ratio", (dcHits + dcMisses) ? (double)dcHits / (dcHits + dcMisses) : NAN);
    add("reencapsulations", reencCount);
    add("reencap_cpu_mean", reencCount ? reencSum / reencCount : NAN);
    add("service_busy_max_s", busyMax);
    add("service_util_max", busyMax / std::max(1e-9, tEnd));
    add("service_served", served);
    add("attack_n", attackN);
    add("attack_delivered", attackDelivered);
    add("lifecycle_intervals", intervals);
    add("intervals_with_stale_grant", intervalsWithStale);
    add("exposure_mean", mean(exposure));
    add("exposure_max", exposure.empty() ? NAN : *std::max_element(exposure.begin(), exposure.end()));
    add("exposure_revoke_mean", mean(exposureRevoke));
    add("inactive_sent", inactiveSent);
    add("inactive_delivered", inactiveDelivered);
    add("inactive_delivery_ratio", inactiveSent ? (double)inactiveDelivered / inactiveSent : NAN);
    add("e2e_exposure_mean", mean(e2eExposure));
    add("e2e_exposure_max", e2eExposure.empty() ? NAN : *std::max_element(e2eExposure.begin(), e2eExposure.end()));
    add("apply_latency_mean", mean(applyLat));
    add("apply_latency_p95", pct(applyLat, 0.95));
    add("apply_latency_max", applyLat.empty() ? NAN : *std::max_element(applyLat.begin(), applyLat.end()));
    add("convergence_mean", mean(convergence));
    add("convergence_max", convergence.empty() ? NAN : *std::max_element(convergence.begin(), convergence.end()));
    add("bytes_total", totalBytes);
    add("bytes_access_control", acBytes);
    add("ac_overhead_ratio", totalBytes ? (double)acBytes / totalBytes : NAN);
    add("bytes_per_satisfied", tp ? (double)totalBytes / tp : NAN);
    add("ac_bytes_per_satisfied", tp ? (double)acBytes / tp : NAN);
    add("ac_bytes_per_interest", nInterestsSent ? (double)acBytes / nInterestsSent : NAN);
    add("bytes_protection", protBytes);
    add("protection_overhead_ratio", totalBytes ? (double)protBytes / totalBytes : NAN);
    add("edge_cs_cross_share", (edgeCsCross + edgeCsSelf) ? (double)edgeCsCross / (edgeCsCross + edgeCsSelf) : NAN);
    add("local_hits", localHits);
    for (int i = 0; i < (int)ByteClass::COUNT; i++) {
        add(std::string("bytes_") + byteClassName((ByteClass)i), linkBytes[i]);
        add(std::string("pkts_") + byteClassName((ByteClass)i), linkPkts[i]);
    }
    for (size_t i = 0; i < row.size(); i++) s << (i ? "," : "") << row[i].first;
    s << "\n";
    for (size_t i = 0; i < row.size(); i++) s << (i ? "," : "") << csv(row[i].second);
    s << "\n";
    s.close();

    if (!detailed) return;
    std::ofstream fi(prefix + "_interests.csv");
    fi << "id,consumer,holder_active,role,unit,t_send,name,sensitivity,expected,attack,attack_type,break_glass,"
          "presentation,interest_bytes,outcome,nack_reason,t_resp,decrypt_ok,plain_bytes\n";
    for (const auto &r : interests)
        fi << r.id << ',' << r.consumer << ',' << r.holderActive << ',' << r.role << ',' << r.unit << ',' << r.tSend << ','
           << r.name << ',' << r.sensitivity << ',' << r.expected << ',' << r.attack << ','
           << r.attackType << ',' << r.breakGlass << ',' << r.presentation << ',' << r.interestBytes
           << ',' << r.outcome << ',' << r.nackReason << ',' << r.tResp << ',' << r.decryptOk << ','
           << r.plainBytes << '\n';
    std::ofstream fd(prefix + "_decisions.csv");
    fd << "t,node,requester,name,verdict,decision_delay,modeled_cpu,measured_cpu,cs_hit,dc_hit,"
          "break_glass,attack,rule,stale_grant\n";
    for (const auto &d : decisions)
        fd << d.t << ',' << d.node << ',' << csv(d.requester) << ',' << d.name << ',' << d.verdict
           << ',' << d.decisionDelay << ',' << d.modeledCpu << ',' << d.measuredCpu << ','
           << d.csHit << ',' << d.decisionCacheHit << ',' << d.breakGlass << ',' << d.attack << ','
           << d.rule << ',' << d.staleGrant << '\n';
    std::ofstream fl(prefix + "_lifecycle.csv");
    fl << "requester,status_index,status,t_start,t_end,stale_grants,last_stale\n";
    for (const auto &kv : lifecycleByRequester)
        for (const auto &iv : kv.second)
            fl << csv(kv.first) << ',' << iv.statusIndex << ',' << iv.status << ',' << iv.tStart << ','
               << iv.tEnd << ',' << iv.staleGrants << ',' << iv.lastStale << '\n';
    std::ofstream fa(prefix + "_applies.csv");
    fa << "version,kind,t_publish,node,t_apply\n";
    for (const auto &kv : applyTime) {
        auto pt = publishTime.find(kv.first);
        for (const auto &nv : kv.second)
            fa << kv.first << ',' << publishKind[kv.first] << ','
               << (pt == publishTime.end() ? -1.0 : pt->second) << ',' << nv.first << ',' << nv.second << '\n';
    }
}

} // namespace ndnpreencryption
