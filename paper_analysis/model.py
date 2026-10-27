"""Analytical model of Section V (Paper A), evaluated with the campus
parameters and the calibrated stage costs, for comparison with simulation.

Every quantity here is an evaluation of the paper's equations; nothing in
this file is read from simulation output except where a function says so
(validation helpers take measured inputs such as hit ratios explicitly)."""
import os
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STAGES = ["did_parse_thumbprint", "interest_sig_verify", "vc_parse_verify", "claims_status_policy",
          "rekey_unseal", "session_lookup", "pre_reencapsulate", "decision_sign", "decision_verify",
          "policy_only"]


def costs():
    v = [float(x) for x in open(os.path.join(ROOT, "simulations", "campus", "cost_model.txt")).read().split()]
    c = dict(zip(STAGES, v[:10]))
    c.update(ed_sign=v[10], ed_verify=v[11], aes_kib=v[12], pre_encap=v[13], pre_decap=v[14])
    return c


# Campus parameters (HospitalCampus.ned, omnetpp.ini [General]).
P = dict(fwd=50e-6, d_acc=0.5e-3, d_edge=1e-3, d_core=1e-3, d_dc=2e-3, d_lan=0.1e-3,
         r_acc=100e6, r_campus=1e9, r_metro=10e9, r_lan=10e9,
         name=50, did=52, n_validators=4)


def tx(bytes_, rate):
    return bytes_ * 8.0 / rate


def pdp_rtt(d_dc, req=214, resp=265):
    """PEP (edge) -> core -> backbone -> DC router -> PDP and back: 4 links, 3 routers each way."""
    one = lambda b: (P["d_edge"] + P["d_core"] + d_dc + P["d_lan"] + 3 * P["fwd"] +
                     tx(b, P["r_campus"]) * 2 + tx(b, P["r_metro"]) + tx(b, P["r_lan"]))
    return one(req) + one(resp)


def validator_rtts(d_dc, req=214, resp=265):
    """Edge in building b: own-core validator (2 links, 1 router), other-core
    validators (4 links, 3 routers), DC validator (like the PDP)."""
    own = 2 * (P["d_edge"] + P["d_core"] + P["fwd"]) + 2 * (tx(req, P["r_campus"]) + tx(resp, P["r_campus"]))
    other = 2 * (P["d_edge"] + 3 * P["d_core"] + 3 * P["fwd"]) + 4 * (tx(req, P["r_campus"]) + tx(resp, P["r_campus"]))
    dc = pdp_rtt(d_dc, req, resp)
    return sorted([own, other, other, dc])


def decision_delay(framework, d_dc=2e-3, hit=0.0, full=False):
    """Eqs. (D1)-(D3): arrival at the edge until the decision is taken."""
    c = costs()
    f = P["fwd"]
    if framework == "edgevc":
        s = c["session_lookup"] + c["interest_sig_verify"] + c["claims_status_policy"]
        if full:
            s = (c["did_parse_thumbprint"] + c["interest_sig_verify"] + c["vc_parse_verify"] +
                 c["claims_status_policy"] + c["rekey_unseal"])
        return f + s
    local = f + c["session_lookup"]
    service = c["interest_sig_verify"] + c["policy_only"] + c["decision_sign"]
    cached = local + c["interest_sig_verify"]
    if framework == "abac":
        miss = local + pdp_rtt(d_dc) + service + c["decision_verify"] + c["rekey_unseal"]
        return hit * cached + (1 - hit) * miss
    if framework == "scbac":
        n = P["n_validators"]; q = 2 * ((n - 1) // 3) + 1
        r = validator_rtts(d_dc)
        # Endorsements arriving together are verified serially by the PEP.
        t_q = r[q - 1] + service
        same = sum(1 for x in r[:q] if abs(x - r[q - 1]) < 1e-4)
        miss = local + t_q + same * c["decision_verify"] + c["rekey_unseal"]
        return hit * cached + (1 - hit) * miss
    raise ValueError(framework)


def exposure_expected(scheme, **kw):
    """Eqs. (E1)-(E4): expected revocation exposure window (s)."""
    if scheme == "push":                      # flood from the issuer to the farthest edge
        c = costs()
        hops = 4                              # issuer->dc->backbone->core->edge routers
        return (P["d_lan"] + kw.get("d_dc", P["d_dc"]) + P["d_core"] + P["d_edge"] +
                hops * (P["fwd"] + c["ed_verify"]))
    if scheme == "pull":                      # uniform phase of the polling timer
        return kw["period"] / 2.0
    if scheme == "pdp":                       # issuer -> PDP on the data-center LAN
        return 2 * P["d_lan"] + P["fwd"]
    if scheme == "ledger":                    # wait for the next block, minus the last-request gap
        return kw["block"] / 2.0
    if scheme == "cache":                     # max over k cached decision keys, minus request gap
        k, ttl, gap = kw["k"], kw["ttl"], kw["gap"]
        return max(0.0, ttl * k / (k + 1.0) - gap)
    raise ValueError(scheme)


def exposure_poisson(lam, a=None, uniform=None):
    """E[W] for a holder sending as a Poisson process of rate lam when the
    enforcement point stops granting A seconds after the change: the expected
    sending time of the last request in [0, A] (0 if none),
    E[W | A] = A - (1 - exp(-lam A)) / lam. `a`: deterministic A;
    `uniform`: A uniform on [0, uniform]."""
    if a is not None:
        return a - (1 - np.exp(-lam * a)) / lam
    u = uniform
    return u / 2 - 1 / lam + (1 - np.exp(-lam * u)) / (lam ** 2 * u)


def apply_loss(p, beacon=1.0, lossy_hops=2):
    """Eq. (wloss): E[apply latency] for link loss p. Two tree hops have a
    single path (metro, backbone-core); an edge misses a version only if
    both its direct link and the two-link path through its partner edge
    lose it (probability ~2p^2)."""
    return _apply_loss(p, beacon, lossy_hops)


def _apply_loss(p, beacon, lossy_hops):
    """
    A one-hop pull round trip is two campus link delays plus forwarding
    and one verification at each end."""
    c = costs()
    t1 = 2 * P["d_core"] + 2 * P["fwd"] + 2 * c["ed_verify"]
    return exposure_expected("push") + (lossy_hops * p + 2 * p * p) * (beacon / 2 + t1)


def exposure_bound(scheme, **kw):
    if scheme == "push":
        return exposure_expected("push", **kw)
    if scheme == "push_loss":                 # every hop may need one beacon round + pull RTT
        return exposure_expected("push", **kw) + kw["hops"] * (kw["beacon"] + kw["pull_rtt"])
    if scheme == "pull":
        return kw["period"]
    if scheme == "cache":
        return kw["ttl"] + exposure_expected("pdp")
    if scheme == "ledger":
        return kw["block"] + exposure_expected("pdp")
    raise ValueError(scheme)


def ac_bytes_per_decision(framework, full=False, vcid=60, diddoc=None, vc=None, d_hops=None):
    """Eq. (O1): access-control bytes added per edge decision (link-level, every hop counted)."""
    req = 24 + P["name"] + P["did"] + 16 + 8 + 64
    resp = 24 + P["did"] + 32 + 93 + 64
    auth = P["did"] + 96                      # L_auth: DID, nonce, timestamp, signature
    if framework == "edgevc":                 # stripped at the edge: one access hop only
        return auth + ((diddoc + vc + vcid + 4) if full else (vcid + 4))
    if framework == "producer":               # identity and credential ride every hop
        return (auth + (diddoc + vc + vcid + 4 if full else vcid + 4)) * (d_hops if d_hops else 6)
    if framework == "abac":
        return auth + (req + resp) * 4
    if framework == "scbac":
        return auth + (req + resp) * (2 + 4 + 4 + 4)
    raise ValueError(framework)


if __name__ == "__main__":
    c = costs()
    for k, v in c.items():
        print(f"{k:24s} {v * 1e6:9.2f} us")
    for d in (1e-3, 2e-3, 5e-3, 10e-3, 20e-3, 40e-3):
        print(f"d_dc={d*1e3:4.0f} ms  EdgeVC {decision_delay('edgevc')*1e3:.3f}  full {decision_delay('edgevc', full=True)*1e3:.3f}"
              f"  C-ABAC {decision_delay('abac', d)*1e3:.3f}  BC-AC {decision_delay('scbac', d)*1e3:.3f} ms")
    print("validator RTTs (ms):", [round(x * 1e3, 3) for x in validator_rtts(2e-3)])
    print("push exposure (ms):", exposure_expected("push") * 1e3)
