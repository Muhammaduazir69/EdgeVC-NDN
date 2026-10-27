"""Result figures of Paper A, generated from simulations/campus/results."""
import glob, os, re, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import style, common as C, model as M

style.setup()
OUT = sys.argv[1] if len(sys.argv) > 1 else "../manuscripts/paperA_ToN/figs"
RES = os.path.join(C.ROOT, "simulations", "campus", "results")
os.makedirs(OUT, exist_ok=True)

ORDER = ["DIDVC", "DIDVC-full", "DIDVC-producer", "DIDVC-key", "ABAC", "ABAC-par", "ABAC-cache", "ABAC-cache-push",
         "ABAC-cache-push-par", "SCBAC", "SCBAC-cache", "SCBAC-cache-push", "NDN"]


def bar(ax, x, m, h, v, **kw):
    ax.bar(x, m, yerr=h, color=style.color(v), edgecolor="white", linewidth=1.0, width=0.72,
           error_kw=dict(lw=0.7, capsize=2, ecolor=style.INK), **kw)


def fig_main():
    df = C.load("Main")
    fig, axs = plt.subplots(1, 3, figsize=(style.COL2, 2.3))
    vs = [v for v in ORDER if v in set(df.iv_variant)]
    xs = np.arange(len(vs))
    labels = [style.name(v) for v in vs]
    # (a) latency
    ax = axs[0]
    for i, v in enumerate(vs):
        g = df[df.iv_variant == v]
        m, h, _ = C.ci(g.latency_mean * 1e3)
        bar(ax, i, m, h, v)
        p, _, _ = C.ci(g.latency_p95 * 1e3)
        ax.plot(i, p, marker="_", ms=9, mew=1.4, color=style.INK)
    ax.set_ylabel("Delivery latency (ms)")
    ax.set_title("(a) mean (bars), 95th percentile (ticks)", fontsize=7)
    # (b) access-control bytes per satisfied request, labels: share of all link bytes
    ax = axs[1]
    for i, v in enumerate(vs):
        if v == "NDN": continue
        g = df[df.iv_variant == v]
        m, h, _ = C.ci(g.ac_bytes_per_satisfied)
        bar(ax, i, m, h, v)
        sh, _, _ = C.ci(g.ac_overhead_ratio * 100)
        ax.text(i, m * 1.35, f"{sh:.0f}%", ha="center", va="bottom", fontsize=5.6, rotation=90)
    ax.set_yscale("log"); ax.set_ylim(50, 1e5)
    ax.set_ylabel("AC bytes per delivery")
    ax.set_title("(b) access-control bytes; labels: share of link bytes", fontsize=7)
    # (c) edge Content Store hit ratio and cross-clinician share
    ax = axs[2]
    for i, v in enumerate(vs):
        g = df[df.iv_variant == v]
        if v.endswith("-par"):      # speculative fetches make the ratio incomparable
            continue
        m, h, _ = C.ci(g.edge_cs_hit_ratio * 100)
        bar(ax, i, m, h, v)
        cs, _, _ = C.ci((g.edge_cs_hit_ratio * g.edge_cs_cross_share).fillna(0) * 100)
        ax.plot(i, cs, marker="o", ms=3.2, mfc="white", mec=style.INK, mew=0.8, ls="none",
                label="served to another clinician" if i == 0 else None)
    ax.set_ylim(0, 45)
    ax.set_ylabel("Edge CS hits (% of granted)")
    ax.set_title("(c) edge cache hits (bars); cross-clinician (o)", fontsize=7)
    ax.legend(fontsize=5.6, loc="upper right", handletextpad=0.3)
    for ax in axs:
        ax.set_xticks(xs); ax.set_xticklabels(labels, rotation=55, ha="right", fontsize=6.3)
    fig.tight_layout(w_pad=0.6)
    style.save(fig, os.path.join(OUT, "fig_main.pdf"))


def fig_distance():
    df = C.load("Distance")
    fig, axs = plt.subplots(1, 2, figsize=(style.COL1, 1.85))
    for v in ["DIDVC", "ABAC", "ABAC-cache", "SCBAC"]:
        g = C.agg(df[df.iv_variant == v], ["iv_dc"], "decision_delay_mean").sort_values("iv_dc")
        axs[0].errorbar(g.iv_dc, g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                        ls="none", ms=3.5, capsize=1.5, label=style.name(v))
        g2 = C.agg(df[df.iv_variant == v], ["iv_dc"], "latency_mean").sort_values("iv_dc")
        axs[1].errorbar(g2.iv_dc, g2["mean"] * 1e3, yerr=g2["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                        ls=style.ls(v), ms=3.5, capsize=1.5)
    d = np.linspace(1, 40, 60)
    hit = df[df.iv_variant == "ABAC-cache"].decision_cache_hit_ratio.mean()
    axs[0].plot(d, [M.decision_delay("edgevc") * 1e3] * len(d), color=style.color("DIDVC"), lw=0.8, alpha=0.7)
    axs[0].plot(d, [M.decision_delay("abac", x * 1e-3) * 1e3 for x in d], color=style.color("ABAC"), lw=0.8, alpha=0.7)
    axs[0].plot(d, [M.decision_delay("abac", x * 1e-3, hit=hit) * 1e3 for x in d], color=style.color("ABAC-cache"), lw=0.8, alpha=0.7)
    axs[0].plot(d, [M.decision_delay("scbac", x * 1e-3) * 1e3 for x in d], color=style.color("SCBAC"), lw=0.8, alpha=0.7)
    axs[0].set_yscale("log")
    axs[0].set_xlabel("$d_{\\mathrm{DC}}$ (ms)"); axs[0].set_ylabel("Decision delay (ms)")
    axs[0].set_title("(a) markers: sim.; lines: model", fontsize=6.5)
    axs[1].set_xlabel("$d_{\\mathrm{DC}}$ (ms)"); axs[1].set_ylabel("Delivery latency (ms)")
    axs[1].set_title("(b) mean delivery latency", fontsize=6.5)
    h_, l_ = axs[0].get_legend_handles_labels()
    fig.legend(h_, l_, loc="upper center", ncol=4, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.88), w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_distance.pdf"))


def fig_cache():
    cs = C.load("CacheSize"); po = C.load("Popularity")
    fig, axs = plt.subplots(1, 2, figsize=(style.COL1, 2.0))
    for v in ["DIDVC", "ABAC", "SCBAC", "NDN"]:
        g = C.agg(cs[cs.iv_variant == v], ["iv_cs"], "latency_mean").sort_values("iv_cs")
        axs[0].errorbar(np.arange(len(g)), g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v),
                        marker=style.marker(v), ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
    axs[0].set_xticks(range(5)); axs[0].set_xticklabels(["0", "50", "150", "300", "1000"])
    axs[0].set_xlabel("Edge CS capacity (records)"); axs[0].set_ylabel("Delivery latency (ms)")
    axs[0].set_title("(a)", fontsize=6.5)
    # (b) latency ratio vs edge hit ratio, both sweeps
    for src, mk in [(cs, "iv_cs"), (po, "iv_alpha")]:
        e = src[src.iv_variant == "DIDVC"].groupby(mk).agg(lat=("latency_mean", "mean"), hit=("edge_cs_hit_ratio", "mean"))
        for v in ["ABAC", "SCBAC"]:
            o = src[src.iv_variant == v].groupby(mk).agg(lat=("latency_mean", "mean"))
            axs[1].plot(e.hit, o.lat / e.lat, color=style.color(v), marker=style.marker(v) if mk == "iv_cs" else "s",
                        ls="none", ms=3.5, mfc="none" if mk == "iv_alpha" else style.color(v),
                        label=f"{style.name(v)} ({'CS size' if mk == 'iv_cs' else 'Zipf $\\alpha$'})")
    # model: rho(h) with T0 fitted on the NDN latency of the CacheSize sweep (linear in h)
    nd = cs[cs.iv_variant == "NDN"].groupby("iv_cs").agg(lat=("latency_mean", "mean"))
    dv = cs[cs.iv_variant == "DIDVC"].groupby("iv_cs").agg(lat=("latency_mean", "mean"), hit=("edge_cs_hit_ratio", "mean"))
    a, b = np.polyfit(dv.hit, nd.lat.values, 1)
    hh = np.linspace(0, 0.9, 40)
    extra = (dv.lat.values - nd.lat.values).mean() - M.decision_delay("edgevc")
    for v, fw in [("ABAC", "abac"), ("SCBAC", "scbac")]:
        T0 = a * hh + b
        rho = (T0 + M.decision_delay(fw) + extra) / (T0 + M.decision_delay("edgevc") + extra)
        axs[1].plot(hh, rho, color=style.color(v), lw=0.8, alpha=0.7)
    axs[1].set_xlabel("EdgeVC edge CS hit ratio $h$"); axs[1].set_ylabel("Ratio $\\rho(h)$")
    axs[1].set_title("(b) markers: sim.; lines: model", fontsize=6.5)
    axs[1].legend(fontsize=5.0, loc="upper left", handletextpad=0.2)
    h_, l_ = axs[0].get_legend_handles_labels()
    fig.legend(h_, l_, loc="upper center", ncol=4, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.88), w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_cache.pdf"))


def fig_revocation():
    df = C.load("Revocation")
    order = ["DIDVC-push", "DIDVC-pull10", "DIDVC-pull60", "DIDVC-producer", "DIDVC-key", "ABAC", "ABAC-cache",
             "ABAC-cache-push", "SCBAC", "SCBAC-cache", "SCBAC-cache-push"]
    names = [style.name(v) if v in style.FW else v for v in order]
    names[0] = "EdgeVC push"
    cols = [style.color(v) for v in order]
    fig, ax = plt.subplots(figsize=(style.COL1, 1.85))
    axs = [ax]
    for i, v in enumerate(order):
        g = df[df.iv_variant == v]
        m, h, _ = C.ci(g.e2e_exposure_mean)
        ax.bar(i, max(m, 1e-3), yerr=h, color=cols[i], edgecolor="white", width=0.72,
               error_kw=dict(lw=0.7, capsize=2))
        if m < 1e-3:
            ax.text(i, 1.4e-3, "0", ha="center", va="bottom", fontsize=6, color=cols[i])
    # model expectations
    exp = {"DIDVC-pull10": M.exposure_expected("pull", period=10),
           "DIDVC-pull60": M.exposure_expected("pull", period=60), "SCBAC": M.exposure_expected("ledger", block=2.0)}
    for i, v in enumerate(order):
        if v in exp:
            ax.plot(i, max(exp[v], 1e-3), marker="D", ms=3.2, mfc="white", mec=style.INK, mew=0.7, ls="none")
    ax.set_yscale("log"); ax.set_ylim(1e-3, 500)
    ax.set_xticks(range(len(order))); ax.set_xticklabels(names, rotation=50, ha="right", fontsize=6)
    ax.set_ylabel("Mean exposure $W$ (s)")
    ax.set_title("bars: simulation; $\\diamond$: model", fontsize=6.5)
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_revocation.pdf"))


def fig_loss():
    df = C.load("Loss")
    fig, axs = plt.subplots(1, 2, figsize=(style.COL1, 1.85))
    pers = sorted(df.iv_per.unique())
    xs = np.arange(len(pers))
    for v in ["DIDVC", "DIDVC-nobeacon", "SCBAC", "ABAC"]:
        g = C.agg(df[df.iv_variant == v], ["iv_per"], "convergence_max").sort_values("iv_per")
        if v != "ABAC":
            axs[0].errorbar(xs, np.maximum(g["mean"], 1e-4), yerr=g["ci"], color=style.color(v), marker=style.marker(v),
                            ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
        g2 = C.agg(df[df.iv_variant == v], ["iv_per"], "e2e_exposure_mean").sort_values("iv_per")
        axs[1].errorbar(xs, np.maximum(g2["mean"], 1e-4), yerr=g2["ci"], color=style.color(v), marker=style.marker(v),
                        ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
    for ax in axs:
        ax.set_xticks(xs); ax.set_xticklabels([f"{p:g}" for p in pers]); ax.set_xlabel("Link packet error rate $p$")
        ax.set_yscale("log")
    axs[0].set_ylabel("Worst status convergence (s)"); axs[0].set_title("(a) max over versions and edges", fontsize=6.5)
    axs[1].set_ylabel("Mean exposure $W$ (s)"); axs[1].set_title("(b) exposure ($W=0$ at $10^{-4}$)", fontsize=6.5)
    h_, l_ = axs[0].get_legend_handles_labels()
    for hh_, ll_ in zip(*axs[1].get_legend_handles_labels()):
        if ll_ not in l_: h_.append(hh_); l_.append(ll_)
    fig.legend(h_, l_, loc="upper center", ncol=4, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.88), w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_loss.pdf"))


def fig_failure():
    df = C.load("Failure")
    fig, ax = plt.subplots(figsize=(style.COL1, 1.7))
    bins = np.arange(20, 601, 10)
    for v in ["DIDVC-issuerDown", "ABAC-pdpDown", "ABAC-cache-pdpDown", "SCBAC-1down", "SCBAC-2down"]:
        curves = []
        for r in df[df.iv_variant == v].run.astype(int):
            f = os.path.join(RES, f"Failure-{r}_interests.csv")
            if not os.path.exists(f): continue
            I = pd.read_csv(f, usecols=["t_send", "expected", "attack", "outcome", "decrypt_ok"])
            I = I[(I.expected == 1) & (I.attack == 0)]
            ok = (I.outcome == 0) & (I.decrypt_ok == 1)
            idx = np.digitize(I.t_send, bins)
            s = pd.Series(ok.values).groupby(idx).mean()
            curves.append(s.reindex(range(1, len(bins))).values)
        if curves:
            c = np.nanmean(np.array(curves, dtype=float), axis=0)
            ax.plot(bins[:-1] + 5, c * 100, color=style.color(v), ls=style.ls(v), lw=1.0, label=style.name(v))
    ax.axvspan(200, 400, color="#fde8e8", zorder=0)
    ax.text(300, 50, "authority down\n(200--400 s)", ha="center", fontsize=6, color="#a33")
    ax.set_xlabel("Simulated time (s)"); ax.set_ylabel("Access success (%)")
    ax.set_ylim(-3, 103)
    ax.legend(fontsize=5.3, loc="lower left", ncol=2, handlelength=1.6)
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_failure.pdf"))


def sca_scalar(path, module_re, name):
    out = []
    pat = re.compile(r"^scalar (\S+) (\S+) (\S+)")
    with open(path) as f:
        for line in f:
            m = pat.match(line)
            if m and m.group(2) == name and re.search(module_re, m.group(1)):
                out.append(float(m.group(3)))
    return out


def fig_scale():
    sc = C.load("Scale"); ec = C.load("EdgeCpu")
    fig, axs = plt.subplots(1, 3, figsize=(style.COL2, 2.0))
    ns = sorted(sc.iv_n.unique())
    for v in ["DIDVC", "DIDVC-full", "ABAC", "ABAC-cache", "SCBAC"]:
        g = C.agg(sc[sc.iv_variant == v], ["iv_n"], "latency_mean").sort_values("iv_n")
        axs[0].errorbar(g.iv_n, g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                        ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
        g2 = C.agg(sc[sc.iv_variant == v], ["iv_n"], "ac_overhead_ratio").sort_values("iv_n")
        axs[1].errorbar(g2.iv_n, g2["mean"] * 100, yerr=g2["ci"] * 100, color=style.color(v), marker=style.marker(v),
                        ls=style.ls(v), ms=3.5, capsize=1.5)
    axs[0].set_xscale("log", base=2); axs[0].set_xticks(ns); axs[0].set_xticklabels([str(n) for n in ns])
    axs[1].set_xscale("log", base=2); axs[1].set_xticks(ns); axs[1].set_xticklabels([str(n) for n in ns])
    axs[0].set_xlabel("Clinicians"); axs[0].set_ylabel("Delivery latency (ms)"); axs[0].set_title("(a)", fontsize=6.5)
    axs[1].set_xlabel("Clinicians"); axs[1].set_ylabel("Access-control share of bytes (%)"); axs[1].set_title("(b)", fontsize=6.5)
    cpus = sorted(ec.iv_cpu.unique())
    for v in ["DIDVC", "DIDVC-full", "ABAC"]:
        g = C.agg(ec[ec.iv_variant == v], ["iv_cpu"], "latency_mean").sort_values("iv_cpu")
        axs[2].errorbar(g.iv_cpu, g["mean"] * 1e3, yerr=g["ci"] * 1e3, color=style.color(v), marker=style.marker(v),
                        ls=style.ls(v), ms=3.5, capsize=1.5, label=style.name(v))
    axs[2].set_xscale("log", base=2); axs[2].set_xticks(cpus); axs[2].set_xticklabels([f"{c:g}x" for c in cpus])
    axs[2].set_yscale("log")
    axs[2].set_xlabel("Edge CPU slowdown factor"); axs[2].set_ylabel("Delivery latency (ms)")
    axs[2].set_title("(c) 60 clinicians at 8 Hz", fontsize=6.5)

    from matplotlib.ticker import ScalarFormatter, NullFormatter
    axs[2].yaxis.set_major_formatter(ScalarFormatter()); axs[2].yaxis.set_minor_formatter(NullFormatter())
    axs[2].set_yticks([5, 10, 20, 40])
    h_, l_ = axs[0].get_legend_handles_labels()
    fig.legend(h_, l_, loc="upper center", ncol=5, fontsize=5.6, frameon=False, handletextpad=0.3, columnspacing=0.9)
    fig.tight_layout(rect=(0, 0, 1, 0.9), w_pad=0.5)
    style.save(fig, os.path.join(OUT, "fig_scale.pdf"))


def fig_tradeoff():
    """Latency against exposure: decision-cache TTL with and without pushed
    invalidation (E9), with EdgeVC and uncached designs from E5."""
    tr = C.load("CacheTradeoff"); rv = C.load("Revocation")
    fig, ax = plt.subplots(figsize=(style.COL1, 1.8))
    for v, mk in [("ABAC-cache", "v"), ("ABAC-cache-push", "<")]:
        g = tr[tr.iv_variant == v].groupby("iv_ttl").agg(lat=("latency_mean", "mean"), exp=("e2e_exposure_mean", "mean")).sort_index()
        ax.plot(g.lat * 1e3, np.maximum(g.exp, 1e-3), color=style.color(v), marker=mk, ls=style.ls(v), label=style.name(v).replace(" + cache", " + cache ($\\tau$)"))
        push = v.endswith("push")
        for t, row in g.iterrows():
            # labels above the no-push curve, below the push curve; the two
            # longest lifetimes sit close together, so offset them apart
            off = {3600: (-14, 4), 300: (4, -7)}.get(int(t), (3, 3)) if not push else ((-6, -9) if int(t) in (1, 30, 3600) else None)
            if off is None: continue
            ax.annotate(f"{t:g} s", (row.lat * 1e3, max(row.exp, 1e-3)), textcoords="offset points", xytext=off, fontsize=5.2)
    for v, lab in [("DIDVC-push", "EdgeVC"), ("ABAC", "C-ABAC"), ("SCBAC", "BC-AC"), ("DIDVC-key", "Key-split")]:
        g = tr[tr.iv_variant == v] if v == "DIDVC-push" else rv[rv.iv_variant == v]
        ax.plot(g.latency_mean.mean() * 1e3, max(g.e2e_exposure_mean.mean(), 1e-3), marker=style.marker(v if v != "DIDVC-push" else "DIDVC"),
                color=style.color(v if v != "DIDVC-push" else "DIDVC"), ls="none", ms=6, label=lab)
    ax.set_yscale("log"); ax.set_ylim(2e-4, 300)
    ax.set_xlabel("Mean delivery latency (ms)"); ax.set_ylabel("Mean exposure $W$ (s)")
    ax.axhspan(2e-4, 1.6e-3, color="#eef1f4", zorder=0)
    ax.text(ax.get_xlim()[1] - 0.2, 2.0e-3, "$W=0$ (drawn at $10^{-3}$)", fontsize=5.2, color="#52606d", ha="right")
    ax.legend(fontsize=5.4, loc="upper right", ncol=1)
    fig.tight_layout()
    style.save(fig, os.path.join(OUT, "fig_tradeoff.pdf"))


if __name__ == "__main__":
    which = sys.argv[2:] or ["main", "distance", "cache", "revocation", "loss", "failure", "scale", "tradeoff"]
    for w in which:
        try:
            globals()["fig_" + w]()
            print("ok", w)
        except SystemExit as e:
            print("skip", w, e)
