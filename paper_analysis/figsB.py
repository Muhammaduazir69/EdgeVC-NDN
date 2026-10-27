"""Result figures and tables of Paper B, generated from simulations/nr5g/results."""
import os, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import style, common as C

style.setup()
OUT = sys.argv[1] if len(sys.argv) > 1 else "../manuscripts/paperB_Access/figs"
TEX = os.path.join(C.ROOT, "manuscripts", "paperB_Access")
RES = os.path.join(C.ROOT, "simulations", "nr5g", "results")
VARS = ["DIDVC", "ABAC", "ABAC-par", "ABAC-cache", "ABAC-cache-push", "SCBAC", "NDN"]


def fig_scale():
    df = C.load("NrScale", "nr5g")
    fig, axs = plt.subplots(1, 3, figsize=(style.COL2, 2.05))
    for v in VARS:
        if v not in set(df.iv_variant): continue
        for ax, col, sc, lab in [(axs[0], "latency_mean", 1e3, "Delivery latency (ms)"),
                                 (axs[1], "decision_delay_mean", 1e3, "Decision delay (ms)"),
                                 (axs[2], "ac_overhead_ratio", 100, "Access-control share of bytes (%)")]:
            if v == "NDN" and col != "latency_mean": continue
            g = C.agg(df[df.iv_variant == v], ["iv_nue"], col).sort_values("iv_nue")
            ax.errorbar(g.iv_nue, np.maximum(g["mean"] * sc, 1e-3), yerr=g["ci"] * sc, color=style.color(v),
                        marker=style.marker(v), ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
            ax.set_ylabel(lab); ax.set_xlabel("Clinician UEs")
    axs[1].set_yscale("log")
    for i, ax in enumerate(axs): ax.set_title(f"({'abc'[i]})", fontsize=6.5)
    h_, l_ = axs[0].get_legend_handles_labels()
    fig.legend(h_, l_, loc="upper center", ncol=7, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.9), w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_nrscale.pdf"))


VERDICT = {0: "Granted", 2: "Signature", 3: "Suspended", 4: "Revoked", 5: "Expired", 6: "Presentation",
           7: "Unavailable", 8: "Replay", 9: "Policy", 10: "Forged credential", 11: "DID/subject binding",
           12: "No credential"}
CLASSES = [("replay", "Replay"), ("forged_vc", "Forged VC"), ("stolen_vc", "Stolen VC"),
           ("did_spoof", "DID spoofing"), ("tampered_vc", "Tampered claims"), ("no_credential", "No credential"),
           ("privilege_escalation", "Tampered claims")]


def attack_table():
    df = C.load("NrAttack", "nr5g")
    recs = []
    for _, r in df.iterrows():
        run = int(r.run)
        I = pd.read_csv(os.path.join(RES, f"NrAttack-{run}_interests.csv"))
        D = pd.read_csv(os.path.join(RES, f"NrAttack-{run}_decisions.csv"))
        I = I[(I.attack == 1) & (I.t_send >= 20)]
        D = D[(D.attack == 1) & (D.t >= 20)]
        # Map decisions to attack classes through the interest names of each class is not
        # possible directly; decisions carry the requester DID. Use per-class requester sets.
        for atype, g in I.groupby("attack_type"):
            recs.append(dict(variant=r.iv_variant, cls=atype, sent=len(g),
                             nack=int((g.outcome == 1).sum()), timeout=int((g.outcome == 2).sum()),
                             readable=int(((g.outcome == 0) & (g.decrypt_ok == 1)).sum()),
                             granted=int((g.outcome == 0).sum()),
                             data_unreadable=int(((g.outcome == 0) & (g.decrypt_ok == 0)).sum()),
                             reason=g[g.outcome == 1].nack_reason.mode().iloc[0] if (g.outcome == 1).any() else -1))
        # edge CPU per attack decision, by verdict
        # Stage that rejected each adversarial request. DENY_BINDING covers two
        # stages with very different costs: the DID thumbprint check (first,
        # cheap) and the VC subject binding (after the VC signature).
        D = D.assign(stage=D.verdict.map(lambda v: VERDICT.get(int(v), str(v))))
        D.loc[(D.verdict == 11) & (D.modeled_cpu < 50e-6), "stage"] = "DID thumbprint"
        D.loc[(D.verdict == 11) & (D.modeled_cpu >= 50e-6), "stage"] = "VC subject binding"
        # A query leaves the PEP unless it was rejected locally (replay, no
        # credential) or answered from the decision cache.
        D = D.assign(remote=((~D.verdict.isin([8, 12])) & (D.dc_hit == 0)).astype(int))
        for st, g in D.groupby("stage"):
            recs.append(dict(variant=r.iv_variant, cls="__verdict", stage=st, n=len(g),
                             cpu=g.modeled_cpu.mean(), delay=g.decision_delay.mean(), remote=int(g.remote.sum())))
    A = pd.DataFrame(recs)
    return A


def tab_attack():
    A = attack_table()
    cls = A[A.cls != "__verdict"]
    rows = []
    order = ["replay", "forged_vc", "stolen_vc", "did_spoof", "tampered_vc", "no_credential"]
    names = dict(CLASSES)
    for c in order:
        cc = [c, "privilege_escalation"] if c == "tampered_vc" else [c]
        g = cls[cls.cls.isin(cc)]
        sent = g[g.variant != "NDN"].groupby("variant").sent.sum()
        line = [names[c], f"{int(sent.mean()):,}"]
        gn = g[g.variant == "NDN"]
        line.append("--" if gn.empty else f"{100 * gn.granted.sum() / gn.sent.sum():.1f}")
        for v in ["DIDVC", "ABAC", "SCBAC"]:
            gv = g[g.variant == v]
            line.append("--" if gv.empty else f"{int(gv.granted.sum()):,}")
        rows.append(" & ".join(line) + " \\\\")
    tex = r"""\begin{table}[!t]
\centering
\caption{Adversary suite over ten replications: requests sent per protected design (mean) and requests answered with Data. The NDN column, without access control, gives the share of its own adversarial requests that were answered.}
\label{tab:attacks}
\footnotesize
\setlength{\tabcolsep}{3pt}
\begin{tabular}{@{}lrrrrr@{}}
\toprule
& & \multicolumn{4}{c}{answered with Data} \\
\cmidrule(lr){3-6}
Class & sent & NDN (\%) & EdgeVC & C-ABAC & BC-AC \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}

\vspace{2pt}
\parbox{\columnwidth}{\footnotesize For the baselines, which carry no credential to tamper with, the tampered-claims class is an enrolled receptionist requesting records of the victim's unit that its role does not permit.}
\end{table}
"""
    open(os.path.join(TEX, "tab_attacks.tex"), "w").write(tex)
    return A


def fig_attack():
    A = attack_table()
    vd = A[A.cls == "__verdict"]
    fig, axs = plt.subplots(1, 2, figsize=(style.COL1, 1.9), gridspec_kw=dict(width_ratios=[1.3, 1]))
    # (a) edge decision CPU per rejected adversarial request, by rejection reason (EdgeVC)
    ev = vd[vd.variant == "DIDVC"]
    e = ev.groupby("stage").apply(lambda g: np.average(g.cpu, weights=g.n), include_groups=False).sort_values()
    labels = list(e.index)
    axs[0].barh(range(len(e)), e.values * 1e6, color=style.color("DIDVC"), edgecolor="white")
    axs[0].set_yticks(range(len(e))); axs[0].set_yticklabels(labels, fontsize=6)
    axs[0].set_xlabel("Edge CPU per rejection ($\\mu$s)")
    axs[0].set_title("(a) EdgeVC, by rejecting stage", fontsize=6.5)
    # (b) remote queries triggered per adversarial request
    vals, cols, labs = [], [], []
    for v, per in [("DIDVC", 0), ("ABAC", 1), ("SCBAC", 4)]:
        g = vd[vd.variant == v]
        tot = g.n.sum()
        vals.append(g.remote.sum() * per / tot if tot else 0); cols.append(style.color(v)); labs.append(style.name(v))
    axs[1].bar(range(3), vals, color=cols, edgecolor="white", width=0.65)
    for i, y in enumerate(vals):
        axs[1].text(i, y + 0.04, f"{y:.2f}", ha="center", va="bottom", fontsize=5.6)
    axs[1].set_ylim(0, max(vals) * 1.15)
    axs[1].set_xticks(range(3)); axs[1].set_xticklabels(labs, fontsize=6.0, rotation=30, ha="right")
    axs[1].set_ylabel("Remote queries per attack")
    axs[1].set_title("(b) load sent upstream", fontsize=6.5)
    fig.tight_layout(w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_attack.pdf"))


def fig_breakglass():
    bg = C.load("NrBreakGlass", "nr5g")
    fig, ax = plt.subplots(figsize=(style.COL1, 1.5))
    xs = np.arange(3)
    for i, v in enumerate(["DIDVC", "ABAC", "SCBAC"]):
        g = bg[bg.iv_variant == v]
        mn, hn, _ = C.ci(g.latency_normal_mean * 1e3)
        mb, hb, _ = C.ci(g.breakglass_scope_latency_mean * 1e3)
        ax.bar(i - 0.18, mn, 0.34, yerr=hn, color=style.color(v), alpha=0.55, edgecolor="white",
               error_kw=dict(lw=0.6, capsize=1.5), label="routine" if i == 0 else None)
        ax.bar(i + 0.18, mb, 0.34, yerr=hb, color=style.color(v), edgecolor="white", hatch="///",
               error_kw=dict(lw=0.6, capsize=1.5), label="emergency-only" if i == 0 else None)
    ax.set_xticks(xs); ax.set_xticklabels([style.name(v) for v in ["DIDVC", "ABAC", "SCBAC"]], fontsize=6.3)
    ax.set_ylabel("Delivery latency (ms)")
    ax.legend(fontsize=5.6, loc="upper left")
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_breakglass.pdf"))


def fig_burst():
    rb = C.load("NrRevocationBurst", "nr5g")
    fig, ax = plt.subplots(figsize=(style.COL1, 1.7))
    bins = np.arange(95, 200, 1.0)
    for v in ["DIDVC", "ABAC", "ABAC-cache", "ABAC-cache-push", "SCBAC"]:
        curves = []
        for r in rb[rb.iv_variant == v].run.astype(int):
            f = os.path.join(RES, f"NrRevocationBurst-{r}_interests.csv")
            if not os.path.exists(f): continue
            I = pd.read_csv(f, usecols=["t_send", "holder_active", "attack", "outcome", "decrypt_ok"])
            I = I[(I.attack == 0) & (I.holder_active == 0) & (I.outcome == 0) & (I.decrypt_ok == 1)]
            h, _ = np.histogram(I.t_send, bins=bins)
            curves.append(np.cumsum(h))
        if curves:
            ax.plot(bins[1:], np.mean(curves, axis=0), color=style.color(v), ls=style.ls(v), lw=1.1, label=style.name(v))
    ax.axvspan(100, 110, color="#fde8e8", zorder=0)
    ax.text(105, ax.get_ylim()[1] * 0.85 if ax.get_ylim()[1] > 0 else 1, "5 revocations", ha="center", fontsize=6, color="#a33")
    ax.set_xlabel("Simulated time (s)"); ax.set_ylabel("Records delivered to\nrevoked clinicians (cum.)")
    ax.legend(fontsize=5.6, loc="center right")
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_burst.pdf"))


def fig_device():
    dv = C.load("NrDevice", "nr5g")
    fig, ax = plt.subplots(figsize=(style.COL1, 1.6))
    for v in ["DIDVC", "ABAC"]:
        g = C.agg(dv[dv.iv_variant == v], ["iv_dev"], "latency_mean").sort_values("iv_dev")
        ax.errorbar(g.iv_dev, g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                    ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
    ax.set_xlabel("Clinician device CPU slowdown factor"); ax.set_ylabel("Delivery latency (ms)")
    ax.legend(fontsize=6)
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_device.pdf"))


def fig_nrdistance():
    df = C.load("NrDistance", "nr5g")
    fig, ax = plt.subplots(figsize=(style.COL1, 2.0))
    for v in ["DIDVC", "ABAC", "ABAC-par", "ABAC-cache-push", "SCBAC"]:
        g = C.agg(df[df.iv_variant == v], ["iv_dc"], "latency_mean").sort_values("iv_dc")
        ax.errorbar(g.iv_dc, g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                    ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
    ax.set_xlabel("One-way delay to the data center (ms)"); ax.set_ylabel("Delivery latency (ms)")
    h_, l_ = ax.get_legend_handles_labels()
    fig.legend(h_, l_, loc="upper center", ncol=3, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.82))
    style.save(fig, os.path.join(OUT, "fig_nrdistance.pdf"))


if __name__ == "__main__":
    which = sys.argv[2:] or ["scale", "attack", "tab_attack", "breakglass", "burst", "device", "nrdistance"]
    for w in which:
        try:
            (globals()["fig_" + w] if not w.startswith("tab") else globals()[w])()
            print("ok", w)
        except (SystemExit, FileNotFoundError, KeyError, ValueError) as e:
            print("skip", w, type(e).__name__, e)
