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
| `framework/` | The GenAI DAST framework (test-case generator, executor, analyser, CI integrator). Containerised and published to GHCR. |
| `results/zap/` | Timestamped ZAP scan outputs. |
| `docs/results/BENCHMARK.md` | Head-to-head results (framework vs ZAP) used in Chapter 4. |

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

## Quick start

With VAMPI running (`cd thesis-target/vampi && docker compose up -d`):

**OWASP ZAP baseline** — `run-zap-scan.sh <label> <host-spec-url> <docker-network> <in-network-base-url>`:

```bash
benchmarks/zap/run-zap-scan.sh vampi-vuln \
  http://localhost:5002/openapi.json vampi_default http://vampi-vulnerable:5000
python3 scoring/score.py --tool zap --mode vulnerable results/zap/vampi-vuln-latest/report.json
```

**GenAI framework** (needs `OPENAI_API_KEY`; see `framework/README.md`):

```bash
# via the published image
docker run --rm --network host -e OPENAI_API_KEY \
  -v "$PWD/out":/work ghcr.io/cheetooh/thesis-framework:latest \
  --target http://localhost:5002 --mode vulnerable --out /work
python3 scoring/score.py --tool framework --mode vulnerable out/findings.json
```

## CI

The companion `thesis-target` repo runs both tools automatically on every push via
GitHub Actions (`.github/workflows/security-scan.yml`) — either on GitHub-hosted
runners (which build a fresh dual-mode VAMPI) or on a self-hosted runner (which
scans a live local container). The framework image is published by this repo's
`.github/workflows/publish.yml`.
