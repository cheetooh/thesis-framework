# thesis-framework

GenAI-enhanced DAST framework for automated **OWASP API Security Top 10 (2023)**
vulnerability testing in CI pipelines, plus the benchmark harness used to compare
it against the **OWASP ZAP** baseline.

This repository is the *product* of the thesis. It is built and published as a
container image (GHCR) and consumed by a developer's project (see the companion
`thesis-target/` repo, which holds the VAMPI application and its CI workflow).

```
 developer commits to  thesis-target (VAMPI)
        │
        ▼
   CI pipeline (GitHub Actions)
        │
        ├── boots target API (vulnerable + secure)
        ├── BASELINE:  OWASP ZAP  api-scan  ─┐
        ├── FRAMEWORK: GenAI DAST scan       ├─► findings
        └── SCORING:   compare vs ground truth ◄┘
                 │
                 ▼
        recall / precision / F1 / FPR / CI overhead
```

## Layout

| Path | Purpose |
|------|---------|
| `ground_truth/vampi_ground_truth.yaml` | Known VAMPI vulnerabilities mapped to OWASP API Top 10 (2023). The scoring oracle. |
| `benchmarks/zap/run-zap-scan.sh` | Runs OWASP ZAP `zap-api-scan.py` against a target's OpenAPI spec; captures JSON/HTML/MD reports + timing. |
| `scoring/score.py` | Parses tool findings, maps to OWASP categories, computes recall/precision/F1/FPR vs ground truth. |
| `framework/` | The GenAI DAST framework (test-case generator, executor, analyser, CI integrator). *(in progress)* |
| `results/zap/` | Timestamped ZAP scan outputs. |
| `docs/` | Methodology notes, mapping tables, figures for Chapter 4. |

## Evaluation design

VAMPI runs in two modes simultaneously (see `thesis-target/vampi/docker-compose.yaml`):

- **vulnerable** (`vulnerable=1`, port 5002) → positive set for **recall** / true positives.
- **secure** (`vulnerable=0`, port 5001) → control for the **false-positive rate**;
  any flag here on a *fixed* vulnerability is a false positive.

Metrics (per the thesis Phase 3 plan):

- **Recall** = TP / (TP + FN) — share of real OWASP API Top 10 issues detected.
- **Precision** = TP / (TP + FP) — share of reported issues that are real.
- **F1** = harmonic mean of precision and recall.
- **False-positive rate** — flags raised on the secure instance for fixed issues.
- **CI overhead** — wall-clock added to the pipeline (captured in `run-meta.json`).

## Quick start (baseline)

```bash
# from the repo root, with VAMPI already up on the vampi_default docker network
benchmarks/zap/run-zap-scan.sh vampi-vuln   http://vampi-vulnerable:5000/openapi.json vampi_default
benchmarks/zap/run-zap-scan.sh vampi-secure http://vampi-secure:5000/openapi.json     vampi_default
python3 scoring/score.py --tool zap --mode vulnerable results/zap/vampi-vuln-latest/report.json
```
