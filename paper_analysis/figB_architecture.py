"""Fig. 1 of Paper B: edge-verified credentials on a 5G SA cell."""
import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, Ellipse, Wedge
import style
from icons2d import *

style.setup()
W, H = 7.16, 3.55
fig = plt.figure(figsize=(W, H))
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
T = dict(fontsize=5.7, color=INK, ha="center", va="top", zorder=20)

# ---------------- radio cell ----------------
ax.add_patch(Ellipse((1.25, 1.25), 2.35, 2.05, fc="#eef6ee", ec="#9ccc9c", lw=0.6, zorder=0))
ax.text(0.2, 2.42, "5G NR standalone cell (Simu5G)", fontsize=6.6, fontweight="bold", color="#2e7d32")
g = (1.25, 1.45)
tower(ax, *g, 0.5)
ax.text(g[0], g[1] - 0.3, "gNB", **T)
clin = [(0.45, 1.75), (0.55, 0.95), (0.95, 0.55), (1.65, 0.55), (2.05, 0.95), (2.1, 1.7), (0.85, 2.05)]
for i, p in enumerate(clin):
    phone(ax, *p, 0.17, TEAL)
    ax.plot([p[0], g[0]], [p[1], g[1] + 0.12], color="#7fb27f", lw=0.4, ls=(0, (2, 2)), zorder=1)
adv = [(1.6, 2.05), (0.3, 1.25)]
for p in adv:
    phone(ax, *p, 0.17, RED)
    ax.plot([p[0], g[0]], [p[1], g[1] + 0.12], color="#e09090", lw=0.4, ls=(0, (2, 2)), zorder=1)
ax.text(0.45, 1.53, "clinician UEs", fontsize=5.8, color=TEAL, ha="center", va="top")
ax.text(1.6, 2.3, "adversary UEs", fontsize=5.8, color=RED, ha="center", va="bottom")

# ---------------- 5G core ----------------
def upf(x, y, label):
    ax.add_patch(FancyBboxPatch((x - 0.2, y - 0.13), 0.4, 0.26, boxstyle="round,pad=0,rounding_size=0.04",
                                fc="#d6e6fa", ec=INK, lw=0.5, zorder=6))
    ax.text(x, y, label, fontsize=6, ha="center", va="center", zorder=7)
iu, u = (2.85, 1.45), (3.65, 1.45)
upf(*iu, "I-UPF"); upf(*u, "UPF")
link(ax, (g[0] + 0.1, g[1]), (iu[0] - 0.2, iu[1]), lw=1.0)
link(ax, (iu[0] + 0.2, iu[1]), (u[0] - 0.2, u[1]), lw=1.0)
ax.text((iu[0] + u[0]) / 2, 1.2, "5G core (GTP-U)", fontsize=5.8, ha="center", va="top", color="#52606d")
n6 = (4.45, 1.45)
router(ax, *n6, 0.2, GOLD); ax.text(n6[0], n6[1] - 0.12, "N6 router", **T)
link(ax, (u[0] + 0.2, u[1]), n6, lw=1.0)
ax.text((u[0] + n6[0]) / 2, 1.5, "N6", fontsize=5.8, ha="center", va="bottom")

# ---------------- edge server ----------------
es = (4.45, 2.5)
server(ax, *es, 0.36, "#5f4b2f")
link(ax, n6, (es[0], es[1] - 0.18), lw=1.0)
ax.text(es[0], es[1] + 0.27, "edge server (local data network)", fontsize=6, ha="center", va="bottom", color=INK)
cx0, cy0, cw, ch = 2.45, 2.2, 1.6, 1.25
ax.add_patch(FancyBboxPatch((cx0, cy0), cw, ch, boxstyle="round,pad=0,rounding_size=0.05", fc="#fbf5e8", ec=GOLD, lw=0.8, zorder=1))
ax.text(cx0 + 0.07, cy0 + ch - 0.05, "Edge enforcement point (NDN/UDP)", fontsize=6.2, fontweight="bold", color="#8a5a00", va="top")
rows = ["credential verifier (DID, VC, replay)", "status-list replica (signed deltas)",
        "policy incl. break-glass rule", "Content Store: one $\\langle C,\\kappa\\rangle$ per record",
        "PRE proxy: $\\kappa'=\\mathrm{ReEnc}(rk_c,\\kappa)$", "audit signer for break-glass grants"]
for i, r in enumerate(rows):
    yy = cy0 + ch - 0.27 - i * 0.157
    ax.add_patch(FancyBboxPatch((cx0 + 0.07, yy - 0.065), cw - 0.14, 0.13, boxstyle="round,pad=0,rounding_size=0.02",
                                fc="white", ec="#e6c98a", lw=0.4, zorder=2))
    ax.text(cx0 + 0.12, yy, r, fontsize=5.4, va="center", color="#3e4c59", zorder=3)
link(ax, (cx0 + cw, 2.75), (es[0] - 0.12, es[1]), color=GOLD, lw=0.6)

# ---------------- data center and partner sites ----------------
ax.add_patch(FancyBboxPatch((5.05, 1.95), 2.0, 1.5, boxstyle="round,pad=0,rounding_size=0.06", fc="#f3f6f9", ec="#9aa5b1", lw=0.6, zorder=0))
ax.text(5.12, 3.41, "Hospital data center ($d_{\\mathrm{DC}}$)", fontsize=6.4, fontweight="bold", color=INK, va="top")
database(ax, 5.35, 2.85, 0.26); ax.text(5.35, 2.66, "EHR\nproducer", **T)
shield(ax, 5.85, 2.86, 0.24); ax.text(5.85, 2.66, "issuer,\naudit log", **T)
padlock(ax, 6.33, 2.88, 0.24); ax.text(6.33, 2.66, "PDP\n(C-ABAC)", **T)
chain(ax, 6.8, 2.86, 0.2); ax.text(6.8, 2.66, "val. 0\n(BC-AC)", **T)
link(ax, n6, (5.15, 2.3), lw=0.9)
ax.add_patch(FancyBboxPatch((5.05, 0.25), 2.0, 1.05, boxstyle="round,pad=0,rounding_size=0.06", fc="#f1f8f4", ec="#9cc8ad", lw=0.6, zorder=0))
ax.text(5.12, 1.26, "Partner sites ($d_{\\mathrm{site}}$)", fontsize=6.4, fontweight="bold", color=INK, va="top")
for i, x in enumerate((5.45, 6.05, 6.65)):
    chain(ax, x, 0.72, 0.2)
    ax.text(x, 0.58, f"validator {i + 1}", **T)
    link(ax, n6, (x, 0.82), color=GREY, lw=0.5)

# ---------------- flows ----------------
c0 = clin[5]
flow(ax, (c0[0] + 0.05, c0[1] + 0.05), (es[0] - 0.2, es[1] - 0.15), BLUE, rad=-0.25, lw=1.0)
badge(ax, 3.05, 2.05, 1, BLUE)
flow(ax, (es[0] - 0.22, es[1] - 0.22), (c0[0] + 0.1, c0[1] - 0.02), GREEN, ls="--", rad=-0.1, lw=1.0)
badge(ax, 3.25, 1.78, 2, GREEN)
flow(ax, (es[0] + 0.15, es[1] + 0.08), (5.75, 3.08), PURPLE, ls="-.", rad=-0.3, lw=0.9)
badge(ax, 5.1, 3.15, 3, PURPLE)
flow(ax, (5.75, 2.75), (es[0] + 0.2, es[1] - 0.06), RED, ls=":", rad=-0.15, lw=1.0)
badge(ax, 5.0, 2.58, 4, RED)
flow(ax, (n6[0] + 0.1, n6[1] + 0.05), (6.28, 2.72), ORANGE, ls="--", rad=-0.35, lw=0.8)
badge(ax, 4.93, 1.83, 5, ORANGE)

lx, ly = 0.12, 0.42
items = [(1, BLUE, "-", "Interest + VC (or VC id), over NR and N6"),
         (2, GREEN, "--", "Data $\\langle C,\\kappa,\\kappa'_c\\rangle$ to one clinician"),
         (3, PURPLE, "-.", "signed audit record (break-glass grant)"),
         (4, RED, ":", "signed status deltas"),
         (5, ORANGE, "--", "PDP query / endorsements (baselines)")]
for i, (n, c, lsy, txt) in enumerate(items):
    xx = lx + (i % 3) * 1.6 if False else lx
for i, (n, c, lsy, txt) in enumerate(items):
    xx, yy = 2.55, 1.0 - i * 0.16
    badge(ax, xx, yy, n, c, r=0.05, fs=5.2)
    ax.plot([xx + 0.08, xx + 0.24], [yy, yy], color=c, ls=lsy, lw=1.0)
    ax.text(xx + 0.28, yy, txt, fontsize=5.3, va="center", ha="left", color=INK)

style.save(fig, sys.argv[1] if len(sys.argv) > 1 else "fig_archB.pdf")
