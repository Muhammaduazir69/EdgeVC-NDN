"""LaTeX tables of Paper A, generated from the same summaries as the figures."""
import os
import numpy as np
import common as C, model as M, style

OUT = os.path.join(C.ROOT, "manuscripts", "paperA_ToN")
ORDER = ["DIDVC", "DIDVC-full", "DIDVC-producer", "DIDVC-key", "ABAC", "ABAC-par", "ABAC-cache", "ABAC-cache-push",
         "ABAC-cache-push-par", "SCBAC", "SCBAC-cache", "SCBAC-cache-push", "NDN"]


def fmt(m, h, d=2, scale=1.0):
    if not np.isfinite(m):
        return "--"
    if h is None or not np.isfinite(h):
        return f"{m * scale:.{d}f}"
    return f"{m * scale:.{d}f}$\\pm${h * scale:.{d}f}"


def tab_main():
    df = C.load("Main")
    rows = []
    for v in ORDER:
        g = df[df.iv_variant == v]
        if g.empty:
            continue
        lm, lh, _ = C.ci(g.latency_mean)
        p95, _, _ = C.ci(g.latency_p95)
        dm, dh, _ = C.ci(g.decision_delay_mean)
        asr, _, _ = C.ci(g.asr)
        ada, _, _ = C.ci(g.ada)
        em, eh, _ = C.ci(g.e2e_exposure_mean)
        ab, _, _ = C.ci(g.ac_bytes_per_satisfied)
        ov, _, _ = C.ci(g.ac_overhead_ratio)
        hit, _, _ = C.ci(g.edge_cs_hit_ratio)
        name = style.name(v)
        if v == "DIDVC":
            name = "\\textbf{" + name + "}"
        rows.append(" & ".join([
            name, fmt(lm, lh, 2, 1e3), f"{p95 * 1e3:.1f}",
            "--" if v == "NDN" else f"{dm * 1e3:.3f}" if dm < 0.001 else f"{dm * 1e3:.2f}",
            f"{asr * 100:.2f}", "--" if v == "NDN" else f"{ada * 100:.2f}",
            "--" if v == "NDN" else fmt(em, eh, 2),
            f"{ab:,.0f}", f"{ov * 100:.1f}", ("--" if v.endswith("-par") else f"{hit * 100:.1f}")]) + " \\\\")
    body = "\n".join(rows)
    tex = r"""\begin{table*}[!t]
\centering
\caption{Baseline Comparison on the Campus (Mean over Ten Replications; $\pm$ Gives the 95\% Confidence Interval)}
\label{tab:main}
\footnotesize
\setlength{\tabcolsep}{3pt}
\begin{tabular}{@{}lrrrrrrrrr@{}}
\toprule
Design & Latency (ms) & p95 (ms) & Decision (ms) & ASR (\%) & ADA (\%) & Exposure $W$ (s) & AC B/req. & AC share (\%) & Edge hit (\%) \\
\midrule
""" + body + r"""
\bottomrule
\end{tabular}
\end{table*}
"""
    open(os.path.join(OUT, "tab_main.tex"), "w").write(tex)


def tab_model():
    main = C.load("Main"); dist = C.load("Distance")
    rows = []
    for v, fw, full, lab in [("DIDVC", "edgevc", False, "EdgeVC, compact"),
                             ("DIDVC-full", "edgevc", True, "EdgeVC, full"),
                             ("ABAC", "abac", False, "C-ABAC"),
                             ("SCBAC", "scbac", False, "BC-AC, $q=3$ of 4")]:
        pred = M.decision_delay(fw, full=full)
        g = main[main.iv_variant == v]
        meas, h, _ = C.ci(g.decision_delay_grant_mean)
        rows.append(f"{lab} & 2 & {pred * 1e3:.3f} & {meas * 1e3:.3f}$\\pm${h * 1e3:.3f} & {(pred - meas) / meas * 100:+.1f} \\\\")
    for dc in (10, 40):
        for v, fw, lab in [("ABAC", "abac", "C-ABAC"), ("SCBAC", "scbac", "BC-AC")]:
            pred = M.decision_delay(fw, dc * 1e-3)
            g = dist[(dist.iv_variant == v) & np.isclose(dist.iv_dc.astype(float), dc)]
            meas, h, _ = C.ci(g.decision_delay_grant_mean)
            rows.append(f"{lab} & {dc} & {pred * 1e3:.3f} & {meas * 1e3:.3f}$\\pm${h * 1e3:.3f} & {(pred - meas) / meas * 100:+.1f} \\\\")
    rv = C.load("Revocation")
    # Network request rate of one clinician (device-cache hits are not sent).
    lam = float((rv.interests / (15 * (rv.t_end - rv.warmup))).mean())
    a_push = M.exposure_expected("push"); a_pdp = M.exposure_expected("pdp")
    exp_rows = [("DIDVC-push", "EdgeVC push", f"{a_push * 1e3:.2f} ms", M.exposure_poisson(lam, a=a_push)),
                ("DIDVC-pull10", "EdgeVC pull, $T_P=10$~s", "$U[0,10]$~s", M.exposure_poisson(lam, uniform=10)),
                ("DIDVC-pull60", "EdgeVC pull, $T_P=60$~s", "$U[0,60]$~s", M.exposure_poisson(lam, uniform=60)),
                ("ABAC", "C-ABAC", f"{a_pdp * 1e3:.2f} ms", M.exposure_poisson(lam, a=a_pdp)),
                ("SCBAC", "BC-AC, $T_B=2$~s", "$U[0,2]$~s", M.exposure_poisson(lam, uniform=2.0))]
    erows = []
    for v, lab, adesc, pred in exp_rows:
        g = rv[rv.iv_variant == v]
        meas, h, _ = C.ci(g.e2e_exposure_mean)
        def sci(x):
            if x == 0: return "0"
            if abs(x) >= 0.01: return f"{x:.2g}"
            mant, ex = f"{x:.1e}".split("e")
            return f"${mant}\\times10^{{{int(ex)}}}$"
        if pred < 0.01:
            # sub-millisecond exposures are shown in microseconds
            u = 1e6
            cell = f"{meas * u:.0f}$\\pm${h * u:.0f}~$\\mu$s"
            erows.append(f"{lab} & {adesc} & {pred * u:.2g}~$\\mu$s & {cell} \\\\")
        else:
            erows.append(f"{lab} & {adesc} & {pred:.2f} & {meas:.2f}$\\pm${h:.2g} \\\\")

    lrows = []
    try:
        loss = C.load("Loss")
        for pp in (0.01, 0.05):
            g = loss[(loss.iv_variant == "DIDVC") & np.isclose(loss.iv_per.astype(float), pp)]
            meas, h, _ = C.ci(g.apply_latency_mean)
            pred = M.apply_loss(pp)
            lrows.append(f"EdgeVC push, $p={pp:g}$ & & {pred * 1e3:.1f} & {meas * 1e3:.1f}$\\pm${h * 1e3:.1f} \\\\")
    except SystemExit:
        pass
    tex = r"""\begin{table}[!t]
\centering
\caption{Model Versus Simulation. Top: Decision Delay of Granted Requests (ms). Middle: Revocation Exposure (s). Bottom: Mean Status Apply Latency under Link Loss}
\label{tab:model}
\footnotesize
\setlength{\tabcolsep}{2pt}
\begin{tabular}{@{}lrrrr@{}}
\toprule
Design & $d_{\mathrm{DC}}$ (ms) & Model & Simulation & Error (\%) \\
\midrule
""" + "\n".join(rows) + r"""
\midrule
Design & $\Delta$ & $\mathbb{E}[W]$, \eqref{eq:wpois} & \multicolumn{2}{r}{$W$ simulation} \\
\midrule
""" + "\n".join(erows) + r"""
\midrule
Loss, $\Delta_e$ (ms) & & \eqref{eq:wloss} & \multicolumn{2}{r}{simulation} \\
\midrule
""" + "\n".join(lrows) + r"""
\bottomrule
\end{tabular}
\end{table}
"""
    open(os.path.join(OUT, "tab_model.tex"), "w").write(tex)


if __name__ == "__main__":
    for f in (tab_main, tab_model):
        try:
            f(); print("ok", f.__name__)
        except (SystemExit, Exception) as e:
            print("skip", f.__name__, e)
