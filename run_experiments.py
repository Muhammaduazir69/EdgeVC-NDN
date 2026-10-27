#!/usr/bin/env python3
"""Run OMNeT++ configurations in parallel; skip runs whose summary exists."""
import os, subprocess, sys, concurrent.futures as cf
ROOT = os.path.dirname(os.path.abspath(__file__))
SIM = os.path.join(ROOT, "simulations", sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in os.listdir(os.path.join(ROOT, "simulations")) else "campus")
args = [a for a in sys.argv[1:] if a not in os.listdir(os.path.join(ROOT, "simulations"))]
jobs = int(os.environ.get("JOBS", "11"))
RUNNER = os.path.join(ROOT, "run_campus.sh") if SIM.endswith("campus") else os.path.join(ROOT, "run_5g.sh")

def numruns(cfg):
    out = subprocess.run([RUNNER, cfg, "", "-q", "numruns"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("Number of runs:"):
            return int(line.split(":")[1])
    raise SystemExit("cannot get run count for %s:\n%s" % (cfg, out))

def one(cfg, r):
    summ = os.path.join(SIM, "results", "%s-%d_summary.csv" % (cfg, r))
    if os.path.exists(summ):
        return cfg, r, "skip"
    log = os.path.join(SIM, "results", "logs", "%s-%d.log" % (cfg, r))
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "w") as f:
        rc = subprocess.run([RUNNER, cfg, str(r)], stdout=f, stderr=subprocess.STDOUT).returncode
    return cfg, r, "ok" if rc == 0 and os.path.exists(summ) else "FAIL rc=%d" % rc

tasks = []
for cfg in args:
    n = numruns(cfg)
    tasks += [(cfg, r) for r in range(n)]
print("runs:", len(tasks), flush=True)
done = 0
with cf.ThreadPoolExecutor(jobs) as ex:
    for cfg, r, st in ex.map(lambda t: one(*t), tasks):
        done += 1
        if st != "skip":
            print("%d/%d %s-%d %s" % (done, len(tasks), cfg, r, st), flush=True)
print("finished", flush=True)
