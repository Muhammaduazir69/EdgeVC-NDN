"""One figure style for both manuscripts: fonts, sizes, palette, markers."""
import matplotlib as mpl
import matplotlib.pyplot as plt

INK, INK2 = "#1f2933", "#52606d"
# Fixed framework -> (display name, color, marker, linestyle). Never cycled.
FW = {
    "DIDVC":          ("EdgeVC",            "#2a78d6", "o", "-"),
    "DIDVC-push":     ("EdgeVC",            "#2a78d6", "o", "-"),
    "DIDVC-full":     ("EdgeVC (full pres.)", "#0f9ba8", "s", "-."),
    "DIDVC-nobeacon": ("EdgeVC (no beacon)", "#0f9ba8", "s", "-."),
    "DIDVC-pull10":   ("EdgeVC pull 10 s",  "#0f9ba8", "s", "-."),
    "DIDVC-pull60":   ("EdgeVC pull 60 s",  "#7b8794", "d", ":"),
    "DIDVC-prio":     ("EdgeVC + priority", "#0f9ba8", "s", "-."),
    "DIDVC-producer": ("Producer-VC",       "#8a5cd1", "D", "--"),
    "DIDVC-key":      ("Key-split",         "#52606d", "h", "--"),
    "ABAC-cache-push": ("C-ABAC + cache + push", "#b5651d", "<", "-."),
    "ABAC-par": ("C-ABAC-par", "#c2378f", "s", ":"),
    "ABAC-cache-push-par": ("C-ABAC + cache + push-par", "#8c4a12", "d", ":"),
    "SCBAC-cache-push": ("BC-AC + cache + push", "#7a1f1f", ">", "-."),
    "DIDVC-issuerDown": ("EdgeVC, issuer down", "#2a78d6", "o", "-"),
    "ABAC":           ("C-ABAC",            "#eb6834", "^", "--"),
    "ABAC-prio":      ("C-ABAC + priority", "#eda100", "v", ":"),
    "ABAC-cache":     ("C-ABAC + cache",    "#eda100", "v", ":"),
    "ABAC-pdpDown":   ("C-ABAC, PDP down",  "#eb6834", "^", "--"),
    "ABAC-cache-pdpDown": ("C-ABAC + cache, PDP down", "#eda100", "v", ":"),
    "SCBAC":          ("BC-AC",             "#1baf7a", "P", "--"),
    "SCBAC-cache":    ("BC-AC + cache",     "#d64545", "X", ":"),
    "SCBAC-1down":    ("BC-AC, 1 validator down", "#1baf7a", "P", "--"),
    "SCBAC-2down":    ("BC-AC, 2 validators down", "#d64545", "X", ":"),
    "NDN":            ("NDN (no AC)",       "#7b8794", ".", ":"),
}

def name(v): return FW[v][0]
def color(v): return FW[v][1]
def marker(v): return FW[v][2]
def ls(v): return FW[v][3]

COL1, COL2 = 3.5, 7.16   # IEEE single / double column widths (in)

def setup():
    mpl.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Nimbus Roman", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
        "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
        "axes.linewidth": 0.6, "grid.linewidth": 0.4, "grid.color": "#d5dae0",
        "axes.grid": True, "grid.linestyle": "-", "axes.axisbelow": True,
        "lines.linewidth": 1.2, "lines.markersize": 4,
        "legend.frameon": False, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42, "ps.fonttype": 42, "figure.dpi": 150,
    })

def save(fig, path):
    fig.savefig(path)
    fig.savefig(path.replace(".pdf", ".png"), dpi=300)
    plt.close(fig)
