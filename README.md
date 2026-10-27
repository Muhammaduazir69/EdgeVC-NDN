# EdgeVC-NDN

Simulation code, configurations and run summaries for two manuscripts:

- **Paper A**: *EdgeVC: Verifying Credentials Where the Cache Is, for Revocable Access Control in Named Data Networking* (submitted to IEEE/ACM Transactions on Networking).
- **Paper B**: *Edge-Verified Credentials for FHIR Access over 5G New Radio: Break-Glass Auditing and an Adversarial Evaluation* (submitted to IEEE Access).

EdgeVC verifies W3C Verifiable Credentials and `did:self` identifiers at the NDN edge router, checks a replicated, signed status list (Bitstring Status List with signed deltas, anti-entropy beacons and snapshots, and a fail-closed staleness bound), and re-encapsulates content keys with single-hop proxy re-encryption (Umbral-style KEM on P-256), so a record is encrypted once and cached once. The baselines are a central policy decision point (C-ABAC, with decision caching, pushed invalidation and speculative fetch) and a validator-quorum design (BC-AC), all running over the same data plane with the same cryptography and calibrated costs.

## Requirements

| Component | Version |
|---|---|
| OMNeT++ | 6.0.3 |
| INET | 4.5 |
| Simu5G | 1.2.2 (Paper B only) |
| OpenSSL | 3.x (`libssl`, `libcrypto`), plus `zlib` |
| Python | 3.10+ with pandas, numpy, scipy, matplotlib (analysis only) |

The Makefile and scripts expect this layout:

```
omnetpp-6.0.3/
  <any folder>/
    inet4.5/
    simu5G/
    EdgeVC-NDN/        <- this repository
```

Set `OMNETPP_ROOT` if the repository is not two levels below the OMNeT++ root.

## Build

```bash
./build.sh            # generates message classes, then builds ./NDNPreEncryption (release)
```

## Run

```bash
./run_campus.sh Main 0          # Paper A, wired hospital campus, configuration Main, run 0
./run_5g.sh NrAttack 0          # Paper B, 5G NR single cell, adversary suite, run 0
JOBS=8 ./run_experiments.py Main Revocation Failure Distance Loss CacheSize Popularity Scale EdgeCpu CacheTradeoff CostCrypto CostForwarding Guards
JOBS=8 ./run_experiments.py nr5g NrScale NrAttack NrBreakGlass NrRevocationBurst NrDevice NrDistance NrPad
```

Each run writes `simulations/<campus|nr5g>/results/<Config>-<run>_summary.csv` and per-request logs (`_interests`, `_decisions`, `_applies`, `_lifecycle`). `run_experiments.py` skips runs whose summary already exists.

| Folder | Paper | Configurations |
|---|---|---|
| `simulations/campus` | A | Main, Revocation, Failure, Distance, Loss, CacheSize, Popularity, Scale, EdgeCpu, CacheTradeoff, CostCrypto, CostForwarding, Guards |
| `simulations/nr5g` | B | NrScale, NrAttack, NrBreakGlass, NrRevocationBurst, NrDevice, NrDistance, NrPad |

Seeds are fixed per run number, so a run reproduces its published summary exactly. The only field that varies between machines is `decision_cpu_measured_mean`, a wall-clock diagnostic of the real OpenSSL call that is not charged as simulated time (simulated processing uses the calibrated cost table) and is not used in either paper.

## Reproduce the figures and numbers

```bash
cd paper_analysis
python3 make_macros.py           # all numbers quoted in both papers (numbers.tex)
python3 figsA.py <out_dir>       # Paper A result figures
python3 figsB.py <out_dir>       # Paper B result figures and tables
python3 tablesA.py <out_dir>     # Paper A tables
```

This repository contains every run summary (`results/*_summary.csv`). A few figures (failure timelines, revocation-burst traces, the attack table) also read the per-request logs, which are too large for git. Download them from the archived release and unpack them into `simulations/*/results/`, or regenerate them with the run commands above.

## Data

The FHIR records in `fhir_corpus/extracted/` are the 10-patient sample bulk export distributed by the Synthea project (synthetic patients, no real health data).

## Citation

See `CITATION.cff`. Please cite the papers above once published.

## Author

Muhammad Uzair, Department of Computer Science, COMSATS University Islamabad, Islamabad 45550, Pakistan. ORCID [0009-0002-4104-2680](https://orcid.org/0009-0002-4104-2680), muhammaduzairr69@gmail.com.

## License

MIT, see `LICENSE`. The Synthea sample records in `fhir_corpus/` are distributed by the Synthea project under its own terms.
