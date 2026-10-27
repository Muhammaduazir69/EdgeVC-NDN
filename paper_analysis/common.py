"""Load per-run summaries and aggregate over seeds with 95% Student-t CIs."""
import glob, os, re
import numpy as np
import pandas as pd
from scipy import stats

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load(cfg, scenario="campus"):
    rows = []
    for f in glob.glob(os.path.join(ROOT, "simulations", scenario, "results", f"{cfg}-*_summary.csv")):
        d = pd.read_csv(f)
        rows.append(d)
    if not rows:
        raise SystemExit(f"no results for {cfg}")
    df = pd.concat(rows, ignore_index=True)
    # itervars like "variant=DIDVC,fw=didvc,...,dc=5-" -> columns
    def parse(s):
        out = {}
        for kv in str(s).rstrip("-").split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                out["iv_" + k] = v.strip('"')
        return out
    iv = pd.DataFrame([parse(s) for s in df["itervars"]])
    df = pd.concat([df, iv], axis=1)
    for c in df.columns:
        if c.startswith("iv_") and c != "iv_variant":
            df[c] = pd.to_numeric(df[c]) if pd.to_numeric(df[c], errors="coerce").notna().all() else df[c]
    return df

def ci(x):
    x = np.asarray([v for v in x if np.isfinite(v)], dtype=float)
    n = len(x)
    if n == 0: return np.nan, np.nan, 0
    m = x.mean()
    if n < 2: return m, 0.0, n
    h = stats.t.ppf(0.975, n - 1) * x.std(ddof=1) / np.sqrt(n)
    return m, h, n

def agg(df, by, metric):
    out = []
    for key, g in df.groupby(by, sort=False):
        m, h, n = ci(g[metric].values)
        rec = dict(zip(by, key if isinstance(key, tuple) else (key,)))
        rec.update(mean=m, ci=h, n=n)
        out.append(rec)
    return pd.DataFrame(out)

def welch(a, b):
    a = np.asarray([v for v in a if np.isfinite(v)]); b = np.asarray([v for v in b if np.isfinite(v)])
    return stats.ttest_ind(a, b, equal_var=False).pvalue
