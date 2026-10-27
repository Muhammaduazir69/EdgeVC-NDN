"""Fig. 1 of Paper A: EdgeVC system overview on the hospital campus."""
import sys
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
from matplotlib.lines import Line2D
import style
from icons2d import *

style.setup()
W, H = 7.16, 3.75
fig = plt.figure(figsize=(W, H))
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
T = dict(fontsize=6.3, color=INK, ha="center", va="top", zorder=20)

# ---------------- data center ----------------
ax.add_patch(FancyBboxPatch((0.12, 2.72), 3.05, 0.92, boxstyle="round,pad=0,rounding_size=0.06",
                            fc="#f3f6f9", ec="#9aa5b1", lw=0.6, zorder=1))
ax.text(0.2, 3.6, "Hospital data center", fontsize=6.8, fontweight="bold", color=INK, va="top")
dc = (2.92, 3.08)
database(ax, 0.48, 3.17, 0.26); ax.text(0.48, 2.98, "EHR producer\n(encrypt once,\nPRE capsule)", **T)
shield(ax, 1.15, 3.18, 0.24); ax.text(1.15, 2.98, "Issuer / data owner\n(VCs, sealed $rk$,\nsigned status list)", **T)
padlock(ax, 1.8, 3.2, 0.24); ax.text(1.8, 2.98, "PDP\n(C-ABAC)", **T)
chain(ax, 2.38, 3.17, 0.24); ax.text(2.38, 2.98, "Validator 0\n(BC-AC)", **T)
router(ax, *dc, 0.22, GOLD); ax.text(dc[0], dc[1] - 0.12, "DC router", **T)
for x in (0.48, 1.15, 1.8, 2.38):
    link(ax, (x, 3.32), (x, 3.42), color="#9aa5b1", lw=0.6)
link(ax, (0.48, 3.42), (2.92, 3.42), color="#9aa5b1", lw=0.6)
link(ax, (2.92, 3.42), dc, color="#9aa5b1", lw=0.6)

# ---------------- campus ----------------
bb = (4.35, 3.08)
router(ax, *bb, 0.22, GOLD); ax.text(bb[0], bb[1] + 0.25, "Campus backbone", fontsize=6.3, ha="center", va="bottom")
link(ax, dc, bb, lw=1.3)
ax.text((dc[0] + bb[0]) / 2, 3.12, "metro link, $d_{\\mathrm{DC}}$", fontsize=6, ha="center", va="bottom", color=INK)
cores = [(2.95, 2.22), (4.35, 2.22), (5.75, 2.22)]
edges = [(2.45, 1.32), (3.35, 1.32), (3.95, 1.32), (4.85, 1.32), (5.35, 1.32), (6.25, 1.32)]
for i, c in enumerate(cores):
    link(ax, bb, c, lw=1.0)
    router(ax, *c, 0.21, PURPLE)
    ax.text(c[0] + 0.17, c[1] + 0.02, f"core {i}", fontsize=6, ha="left", va="center")
    chain(ax, c[0] - 0.36, c[1] + 0.3, 0.16, GREEN)
    if i == 0: ax.text(c[0] - 0.36, c[1] + 0.39, f"validator {i + 1}", fontsize=5.6, ha="center", va="bottom", color="#3e4c59")
    link(ax, (c[0] - 0.36, c[1] + 0.24), c, color=GREY, lw=0.5, ls=":")
for j, e in enumerate(edges):
    link(ax, cores[j // 2], e, lw=0.9)
    router(ax, *e, 0.2, BLUE)
    if j % 2 == 0:
        link(ax, e, edges[j + 1], lw=0.6, ls="--", color=GREY)
ax.text(4.35, 0.98, "edge routers: EdgeVC enforcement points and PRE proxies", fontsize=6, ha="center", va="center", color=BLUE, zorder=20, bbox=dict(fc="white", ec="none", pad=0.6))
# clinicians
roles = ["ICU", "ED", "Rad.", "Pharm.", "Surg.", "Onc."]
for j, e in enumerate(edges):
    for k, dx in enumerate((-0.17, 0.17)):
        p = (e[0] + dx, 0.5)
        (laptop if k == 0 else phone)(ax, *p, 0.17)
        link(ax, e, (p[0], p[1] + 0.1), lw=0.5, color=GREY)
    ax.text(e[0], 0.29, roles[j], fontsize=5.8, ha="center", va="top", color="#52606d")
ax.text(4.35, 0.12, "clinicians (did:self holders with W3C VCs)", fontsize=6.2, ha="center", va="bottom", color=INK)

# ---------------- EdgeVC internals callout ----------------
cx0, cy0, cw, ch = 0.08, 0.2, 1.95, 2.35
ax.add_patch(FancyBboxPatch((cx0, cy0), cw, ch, boxstyle="round,pad=0,rounding_size=0.05",
                            fc="#eef5fd", ec=BLUE, lw=0.8, zorder=1))
ax.text(cx0 + 0.08, cy0 + ch - 0.06, "EdgeVC edge router", fontsize=6.8, fontweight="bold", color=BLUE, va="top")
blocks = [
    ("Credential verifier", "DID $\\leftrightarrow$ key thumbprint, Ed25519\nInterest signature, VC proof, subject\nbinding, validity, replay window"),
    ("Status-list replica", "issuer-signed deltas + snapshots,\nanti-entropy beacons, version $v$"),
    ("Policy (name-derived)", "unit, FHIR type, sensitivity read from\nthe name, never from the requester"),
    ("Content Store + PRE proxy", "caches $\\langle C,\\kappa\\rangle$ once; per grant\n$\\kappa'=\\mathrm{ReEnc}(rk_{o\\rightarrow c},\\kappa)$"),
]
by = cy0 + ch - 0.3
for name, desc in blocks:
    ax.add_patch(FancyBboxPatch((cx0 + 0.07, by - 0.42), cw - 0.14, 0.43, boxstyle="round,pad=0,rounding_size=0.03",
                                fc="white", ec="#9cc2ec", lw=0.5, zorder=2))
    ax.text(cx0 + 0.13, by - 0.02, name, fontsize=6.1, fontweight="bold", color=INK, va="top", zorder=3)
    ax.text(cx0 + 0.13, by - 0.13, desc, fontsize=5.4, color="#3e4c59", va="top", zorder=3, linespacing=1.05)
    by -= 0.5
link(ax, (cx0 + cw, 1.5), (edges[0][0] - 0.12, edges[0][1] + 0.03), color=BLUE, lw=0.7, ls="-")

# ---------------- flows ----------------
e0 = edges[0]; c0 = (e0[0] - 0.17, 0.62)
flow(ax, (c0[0] - 0.02, c0[1] + 0.02), (e0[0] - 0.08, e0[1] - 0.08), BLUE, rad=0.25)
badge(ax, e0[0] - 0.34, 0.95, 1, BLUE)
flow(ax, (e0[0] + 0.06, e0[1] - 0.08), (e0[0] + 0.17, 0.66), GREEN, ls="--", rad=0.2)
badge(ax, e0[0] + 0.3, 0.95, 4, GREEN)
flow(ax, (e0[0] + 0.03, e0[1] + 0.08), (cores[0][0] - 0.1, cores[0][1] - 0.08), GREY, rad=-0.15)
badge(ax, 2.55, 1.84, 2, GREY)
flow(ax, (cores[0][0] - 0.03, cores[0][1] - 0.1), (e0[0] + 0.1, e0[1] + 0.07), GREEN, rad=-0.15)
badge(ax, 2.9, 1.7, 3, GREEN)
# status deltas flooded from the issuer
flow(ax, (1.3, 3.05), (dc[0] - 0.08, dc[1] + 0.03), RED, ls=":", rad=0.0, lw=1.0)
flow(ax, (bb[0] + 0.1, bb[1] - 0.06), (cores[2][0] - 0.06, cores[2][1] + 0.08), RED, ls=":", rad=-0.1)
flow(ax, (cores[2][0] + 0.04, cores[2][1] - 0.09), (edges[5][0] - 0.03, edges[5][1] + 0.08), RED, ls=":", rad=-0.1)
badge(ax, 5.98, 2.7, 5, RED)
# baseline request path (dimmed)
flow(ax, (edges[3][0] + 0.02, edges[3][1] + 0.08), (cores[1][0] + 0.08, cores[1][1] - 0.08), ORANGE, ls="--", rad=0.15, lw=0.8)
flow(ax, (cores[1][0] + 0.1, cores[1][1] + 0.08), (bb[0] + 0.05, bb[1] - 0.08), ORANGE, ls="--", rad=0.15, lw=0.8)
flow(ax, (bb[0] - 0.12, bb[1] + 0.06), (1.95, 3.32), ORANGE, ls="--", rad=0.35, lw=0.8)
badge(ax, 4.62, 1.84, 6, ORANGE)

# ---------------- legend ----------------
lx, ly = 6.42, 3.62
items = [(1, BLUE, "-", "Interest + VC or VC reference"),
         (2, GREY, "-", "stripped Interest (CS miss)"),
         (3, GREEN, "-", "Data $\\langle C,\\kappa\\rangle$, cached once"),
         (4, GREEN, "--", "Data $\\langle C,\\kappa,\\kappa'_c\\rangle$ per clinician"),
         (5, RED, ":", "signed status deltas (flood)"),
         (6, ORANGE, "--", "PDP query / endorsements (baselines)")]
ax.add_patch(FancyBboxPatch((lx - 1.32, ly - 1.02), 1.98, 1.06, boxstyle="round,pad=0,rounding_size=0.04",
                            fc="white", ec="#c7ced6", lw=0.5, zorder=15))
for i, (n, c, lsy, txt) in enumerate(items):
    yy = ly - 0.1 - i * 0.165
    badge(ax, lx - 1.22, yy, n, c, r=0.055, fs=5.4, z=16)
    ax.plot([lx - 1.13, lx - 0.93], [yy, yy], color=c, ls=lsy, lw=1.0, zorder=16)
    ax.text(lx - 0.88, yy, txt, fontsize=5.4, va="center", ha="left", color=INK, zorder=16)

out = sys.argv[1] if len(sys.argv) > 1 else "fig_architecture.pdf"
style.save(fig, out)
