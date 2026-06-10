# GenAI DAST framework (`genai_dast`)

A Generative-AI-augmented Dynamic Application Security Testing engine for the
**OWASP API Security Top 10 (2023)**. It is the "product" evaluated in the thesis
against the OWASP ZAP baseline.

## Architecture (Chapter 3)

| Module | File | Role |
|--------|------|------|
| CI Integrator | `scan.py` | Entry point; seeds + summarises the target; orchestrates the run; emits findings. |
| Test Case Generator | `llm.py` → `generate_payloads()` | GPT-4 produces schema-aware attack payloads per OWASP category. |
| DAST Executor | `strategies.py`, `target.py` | Nine modular drivers run the multi-step attacks against the live API. |
| Result Analyser | `llm.py` → `verify_finding()` | GPT-4 verifies each candidate from request/response evidence, cutting false positives. |

GenAI does the **payload synthesis** and the **verdict/response analysis**; the
drivers provide reliable multi-step orchestration (auth bootstrap, object
creation, cross-user access). This is the hybrid design described in Chapter 3.

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
python -m genai_dast.scan --target http://localhost:5000 --mode vulnerable --out results
```

Outputs in `--out`:
- `findings.json` — normalized findings (score with `scoring/score.py --tool framework`)
- `report.md` — human-readable findings with rationale + remediation
- `run-meta.json` — timing (CI overhead) + config

## Run via container (as CI does)

```bash
docker run --rm --network host -e OPENAI_API_KEY \
  -v "$PWD/out":/work \
  ghcr.io/cheetooh/thesis-framework:latest \
  --target http://localhost:5000 --mode vulnerable --out /work
```

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `OPENAI_API_KEY` | – | required for GenAI generation + verification |
| `OPENAI_MODEL` | `gpt-4o` | any GPT-4-class model the key can access |

If no key is set, drivers fall back to their deterministic heuristic oracles so
the pipeline still runs (with reduced "AI verification").
