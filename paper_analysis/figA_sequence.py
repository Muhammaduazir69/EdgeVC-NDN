"""Fig. 2 of Paper A: EdgeVC message sequence (one clinician, one edge)."""
import sys
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
import style
from icons2d import *

style.setup()
W, H = 3.5, 4.95
fig = plt.figure(figsize=(W, H))
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")

lanes = {"Clinician": 0.4, "Edge (EdgeVC)": 1.32, "Transit / producer": 2.3, "Issuer": 3.05}
top = H - 0.18
for name, x in lanes.items():
    ax.add_patch(FancyBboxPatch((x - 0.36, top - 0.17), 0.72, 0.19, boxstyle="round,pad=0,rounding_size=0.03",
                                fc="#eef2f6", ec="#9aa5b1", lw=0.5, zorder=3))
    ax.text(x, top - 0.075, name, fontsize=5.4, ha="center", va="center", fontweight="bold", color=INK, zorder=4)
    ax.plot([x, x], [0.08, top - 0.17], color="#b8c2cc", lw=0.6, ls="--", zorder=1)

def msg(y, a, b, text, color=INK, ls="-", above=True, fs=5.3):
    xa, xb = lanes[a], lanes[b]
    ax.annotate("", xy=(xb, y), xytext=(xa, y),
                arrowprops=dict(arrowstyle="-|>", lw=0.8, color=color, ls=ls, mutation_scale=6), zorder=5)
    ax.text((xa + xb) / 2, y + (0.025 if above else -0.025), text, fontsize=fs, ha="center",
            va="bottom" if above else "top", color=color, zorder=6)

def act(y, lane, text, color=BLUE, h=None, w=1.06, fs=5.0):
    x = lanes[lane]
    if h is None: h = 0.05 + 0.085 * (text.count("\n") + 1)
    x = min(x, W - w / 2 - 0.03)
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle="round,pad=0,rounding_size=0.025",
                                fc="white", ec=color, lw=0.6, zorder=7))
    ax.text(x, y, text, fontsize=fs, ha="center", va="center", color=INK, zorder=8, linespacing=1.0)

def phase(y, text):
    ax.add_patch(Rectangle((0.02, y - 0.075), W - 0.04, 0.15, fc="#f6f8fa", ec="none", zorder=0))
    ax.text(0.05, y, text, fontsize=5.6, fontweight="bold", color="#52606d", va="center", zorder=2)

y = top - 0.36
phase(y, "Enrollment (once)")
y -= 0.2; msg(y, "Clinician", "Issuer", "did:self, DID doc, PRE key, signature")
y -= 0.22; act(y, "Issuer", "roster check; VC + sealed\n$rk_{o\\rightarrow c}$, status index $i$", RED, w=0.8)
y -= 0.2; msg(y, "Issuer", "Clinician", "VC (W3C VC 2.0, Ed25519 proof)", above=False)

y -= 0.25; phase(y, "First request: full presentation, CS miss")
y -= 0.2; msg(y, "Clinician", "Edge (EdgeVC)", "Interest $n$ + DID doc + VC + sig", BLUE)
y -= 0.32; act(y, "Edge (EdgeVC)", "thumbprint, Ed25519, VC proof,\nbinding, status[$i$], policy($n$);\nunseal $rk$, store session")
y -= 0.33; msg(y, "Edge (EdgeVC)", "Transit / producer", "stripped Interest $n$", GREY)
y -= 0.2; msg(y, "Transit / producer", "Edge (EdgeVC)", "Data $\\langle C,\\kappa\\rangle$ (cached)", GREEN, above=False)
y -= 0.22; act(y, "Edge (EdgeVC)", "$\\kappa'=\\mathrm{ReEnc}(rk,\\kappa)$", GREEN)
y -= 0.17; msg(y, "Edge (EdgeVC)", "Clinician", "Data $\\langle C,\\kappa,\\kappa'\\rangle$", GREEN, ls="--", above=False)
y -= 0.2; act(y, "Clinician", "$K=\\mathrm{Dec}_b(\\kappa')$,\nAES-GCM open", TEAL, w=0.66)

y -= 0.25; phase(y, "Later requests: compact presentation, CS hit")
y -= 0.2; msg(y, "Clinician", "Edge (EdgeVC)", "Interest $n'$ + vcId + sig", BLUE)
y -= 0.22; act(y, "Edge (EdgeVC)", "session, Ed25519, status, policy;\nCS hit, ReEnc")
y -= 0.2; msg(y, "Edge (EdgeVC)", "Clinician", "Data $\\langle C',\\kappa_{n'},\\kappa'_{n'}\\rangle$", GREEN, ls="--", above=False)

y -= 0.25; phase(y, "Revocation")
y -= 0.2; msg(y, "Issuer", "Edge (EdgeVC)", "signed delta (v+1, $i$, revoked), flooded", RED, ls=":")
y -= 0.2; msg(y, "Clinician", "Edge (EdgeVC)", "Interest $n''$ + vcId + sig", BLUE)
y -= 0.18; msg(y, "Edge (EdgeVC)", "Clinician", "NACK (revoked)", RED, above=False)

style.save(fig, sys.argv[1] if len(sys.argv) > 1 else "fig_sequence.pdf")
