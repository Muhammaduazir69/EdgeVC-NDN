"""Flat vector icons in data coordinates (1 unit = 1 inch when the axes are
set up with figure-inch limits). Shared by the architecture figures of both
manuscripts so that node classes look the same everywhere."""
import numpy as np
from matplotlib.patches import (Circle, Ellipse, FancyBboxPatch, Polygon,
                                Rectangle, Wedge, FancyArrowPatch)

INK = "#1f2933"
BLUE, ORANGE, GREEN, GOLD = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
PURPLE, TEAL, RED, GREY = "#8a5cd1", "#0f9ba8", "#d64545", "#7b8794"


def router(ax, x, y, s=0.22, color=BLUE, z=6):
    """NDN forwarder: short cylinder with four arrows on top."""
    w, h = s, s * 0.36
    ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, fc=color, ec=INK, lw=0.5, zorder=z))
    ax.add_patch(Ellipse((x, y - h / 2), w, h * 0.7, fc=color, ec=INK, lw=0.5, zorder=z - 0.1))
    ax.add_patch(Ellipse((x, y + h / 2), w, h * 0.7, fc="#d6e6fa", ec=INK, lw=0.5, zorder=z + 0.1))
    a = s * 0.16
    for dx, dy in [(-1, 0), (1, 0)]:
        ax.annotate("", xy=(x + dx * a * 1.5, y + h / 2), xytext=(x + dx * a * 0.3, y + h / 2),
                    arrowprops=dict(arrowstyle="-|>", lw=0.5, color=INK, mutation_scale=4), zorder=z + 0.2)


def server(ax, x, y, s=0.26, color="#455a64", z=6, units=3):
    w, h = s * 0.62, s
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle="round,pad=0,rounding_size=0.015",
                                fc=color, ec=INK, lw=0.5, zorder=z))
    for i in range(units):
        yy = y - h / 2 + h * (i + 0.5) / units
        ax.add_patch(Rectangle((x - w * 0.38, yy - h * 0.06), w * 0.76, h * 0.12, fc="#cfd8dc", ec="none", zorder=z + 0.1))
        ax.add_patch(Circle((x + w * 0.28, yy), s * 0.025, fc=GREEN, ec="none", zorder=z + 0.2))


def database(ax, x, y, s=0.24, color=GREEN, z=6):
    w, h = s * 0.7, s * 0.8
    ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, fc=color, ec=INK, lw=0.5, zorder=z))
    for k in (-0.5, -0.17, 0.17):
        ax.add_patch(Ellipse((x, y + k * h), w, h * 0.28, fc=color, ec=INK, lw=0.4, zorder=z + 0.05))
    ax.add_patch(Ellipse((x, y + h / 2), w, h * 0.28, fc="#c9f0dd", ec=INK, lw=0.5, zorder=z + 0.1))


def laptop(ax, x, y, s=0.18, color=TEAL, z=6):
    w, h = s, s * 0.62
    ax.add_patch(FancyBboxPatch((x - w * 0.42, y - h * 0.05), w * 0.84, h * 0.62, boxstyle="round,pad=0,rounding_size=0.01",
                                fc="#e8f4fb", ec=INK, lw=0.5, zorder=z))
    ax.add_patch(Rectangle((x - w * 0.36, y + h * 0.02), w * 0.72, h * 0.48, fc=color, ec="none", zorder=z + 0.1))
    ax.add_patch(Polygon([[x - w / 2, y - h * 0.05], [x + w / 2, y - h * 0.05], [x + w * 0.42, y - h * 0.22],
                          [x - w * 0.42, y - h * 0.22]], closed=True, fc="#b0bec5", ec=INK, lw=0.5, zorder=z))


def phone(ax, x, y, s=0.16, color=TEAL, z=6):
    w, h = s * 0.5, s
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle="round,pad=0,rounding_size=0.015",
                                fc=INK, ec=INK, lw=0.5, zorder=z))
    ax.add_patch(Rectangle((x - w * 0.38, y - h * 0.36), w * 0.76, h * 0.72, fc=color, ec="none", zorder=z + 0.1))


def shield(ax, x, y, s=0.22, color=RED, z=6, glyph="key"):
    """Credential issuer: shield with a key-hole."""
    pts = [[x - s * 0.4, y + s * 0.45], [x + s * 0.4, y + s * 0.45], [x + s * 0.4, y],
           [x, y - s * 0.5], [x - s * 0.4, y]]
    ax.add_patch(Polygon(pts, closed=True, fc=color, ec=INK, lw=0.5, zorder=z))
    ax.add_patch(Circle((x, y + s * 0.12), s * 0.11, fc="white", ec="none", zorder=z + 0.1))
    ax.add_patch(Polygon([[x - s * 0.05, y + s * 0.08], [x + s * 0.05, y + s * 0.08], [x + s * 0.08, y - s * 0.22],
                          [x - s * 0.08, y - s * 0.22]], closed=True, fc="white", ec="none", zorder=z + 0.1))


def padlock(ax, x, y, s=0.22, color=ORANGE, z=6):
    """Central PDP (policy decision point)."""
    ax.add_patch(Wedge((x, y + s * 0.08), s * 0.22, 0, 180, width=s * 0.07, fc=INK, ec=INK, lw=0.4, zorder=z))
    ax.add_patch(FancyBboxPatch((x - s * 0.32, y - s * 0.42), s * 0.64, s * 0.5, boxstyle="round,pad=0,rounding_size=0.02",
                                fc=color, ec=INK, lw=0.5, zorder=z + 0.1))
    ax.add_patch(Circle((x, y - s * 0.16), s * 0.06, fc=INK, ec="none", zorder=z + 0.2))


def chain(ax, x, y, s=0.22, color=GREEN, z=6):
    """Ledger validator: three linked blocks."""
    b = s * 0.3
    for i, dx in enumerate((-0.36, 0.0, 0.36)):
        ax.add_patch(Rectangle((x + dx * s - b / 2, y - b / 2 + (i % 2) * b * 0.25), b, b, fc=color, ec=INK, lw=0.5, zorder=z))
    ax.plot([x - 0.36 * s + b / 2, x - b / 2], [y, y + b * 0.1], color=INK, lw=0.6, zorder=z - 0.1)
    ax.plot([x + b / 2, x + 0.36 * s - b / 2], [y + b * 0.1, y], color=INK, lw=0.6, zorder=z - 0.1)


def tower(ax, x, y, s=0.4, color=INK, z=5):
    """gNB: lattice mast with radiating arcs."""
    ax.add_patch(Polygon([[x - s * 0.18, y - s / 2], [x + s * 0.18, y - s / 2], [x + s * 0.03, y + s * 0.4],
                          [x - s * 0.03, y + s * 0.4]], closed=True, fc="none", ec=color, lw=0.8, zorder=z))
    for k in range(1, 4):
        yy = y - s / 2 + k * s * 0.22
        ww = s * 0.18 * (1 - k * 0.22)
        ax.plot([x - ww, x + ww], [yy, yy], color=color, lw=0.6, zorder=z)
    for r in (0.12, 0.2):
        for sgn in (-1, 1):
            th = np.linspace(-40, 40, 20) + (0 if sgn > 0 else 180)
            ax.plot(x + r * s * np.cos(np.radians(th)), y + s * 0.4 + r * s * np.sin(np.radians(th)),
                    color=color, lw=0.7, zorder=z)


def hospital(ax, x, y, w=0.6, h=0.42, color="#dfe7ef", z=2):
    ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, fc=color, ec="#9aa5b1", lw=0.5, zorder=z))
    for i in range(4):
        for j in range(3):
            ax.add_patch(Rectangle((x - w / 2 + w * (0.1 + 0.22 * i), y - h / 2 + h * (0.12 + 0.28 * j)), w * 0.12, h * 0.16,
                                   fc="#c4d3e0", ec="none", zorder=z + 0.1))
    ax.add_patch(Rectangle((x - w * 0.04, y + h * 0.3), w * 0.08, h * 0.16, fc=RED, ec="none", zorder=z + 0.2))
    ax.add_patch(Rectangle((x - w * 0.09, y + h * 0.35), w * 0.18, h * 0.06, fc=RED, ec="none", zorder=z + 0.2))


def link(ax, a, b, color=INK, lw=0.8, ls="-", z=3, alpha=1.0):
    ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, ls=ls, zorder=z, alpha=alpha, solid_capstyle="round")


def flow(ax, a, b, color=BLUE, ls="-", lw=1.0, rad=0.0, z=8, head="-|>", ms=7):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=head, mutation_scale=ms, color=color, lw=lw, ls=ls,
                                 connectionstyle=f"arc3,rad={rad}", zorder=z, shrinkA=2, shrinkB=2))


def badge(ax, x, y, n, color=INK, r=0.065, z=12, fs=6):
    ax.add_patch(Circle((x, y), r, fc=color, ec="white", lw=0.6, zorder=z))
    ax.text(x, y, str(n), ha="center", va="center", color="white", fontsize=fs, fontweight="bold", zorder=z + 1)
