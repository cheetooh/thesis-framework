"""
Orchestrator + CLI for the GenAI DAST framework.

Flow (Chapter 3 architecture):
  1. CI Integrator   — parse args, seed + summarise the target API.
  2. Test Generator  — each driver asks GPT-4 for payloads (inside strategies.py).
  3. DAST Executor   — drivers run the multi-step attacks against the target.
  4. Result Analyser — GPT-4 verifies each candidate from its evidence + oracle,
                       reducing false positives; final findings are emitted.

Output:
  * findings.json — normalized findings (scorable with scoring/score.py --tool framework)
  * report.md     — human-readable report with rationale + remediation
  * run-meta.json — timing (CI overhead) + config

Usage:
  python -m genai_dast.scan --target http://localhost:5002 --mode vulnerable \
      --out /work/results
"""
from __future__ import annotations
import argparse
import json
import os
import time
from urllib.parse import urlparse

import requests

from .llm import LLM, DEFAULT_MODEL
from .target import Target
from .strategies import ALL_DRIVERS, Candidate


def base_from(target: str) -> str:
    """Accept either a base URL or an OpenAPI URL; return the base URL."""
    p = urlparse(target)
    if not p.scheme:
        return "http://" + target.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def summarize_spec(base_url: str) -> str:
    """Compact OpenAPI context for the LLM (endpoints + key schemas)."""
    for path in ("/openapi.json", "/swagger.json"):
        try:
            r = requests.get(base_url + path, timeout=15)
            if r.status_code == 200:
                spec = r.json()
                lines = []
                for p, item in (spec.get("paths") or {}).items():
                    for method, op in item.items():
                        if isinstance(op, dict):
                            lines.append(f"{method.upper()} {p} - {op.get('summary', '')}".strip())
                schemas = (spec.get("components") or {}).get("schemas", {})
                ctx = "Endpoints:\n" + "\n".join(sorted(lines)[:40])
                if schemas:
                    ctx += "\n\nSchemas: " + json.dumps(schemas)[:1200]
                return ctx[:3000]
        except requests.RequestException:
            continue
    return "(OpenAPI spec unavailable)"


def run_scan(target: str, mode: str, model: str | None) -> dict:
    base_url = base_from(target)
    t = Target(base_url=base_url, timeout=20)
    llm = LLM(model=model)

    t.seed_db()                                   # ensure VAMPI db is populated
    ctx = summarize_spec(base_url)

    started = time.time()
    findings = []
    candidates: list[Candidate] = []
    for driver in ALL_DRIVERS:
        try:
            cand = driver(t, llm, ctx)
        except Exception as exc:                  # a broken driver shouldn't kill the scan
            print(f"[warn] driver {driver.__name__} errored: {exc}")
            continue
        candidates.append(cand)

        # Result Analyser (GPT-4) verifies the candidate from its evidence.
        verdict = llm.verify_finding(cand.owasp, cand.endpoint, cand.attack_description,
                                     cand.success_oracle, cand.evidence())
        if verdict:
            is_vuln = bool(verdict.get("vulnerable"))
            confidence = float(verdict.get("confidence", 0.5))
            rationale = verdict.get("rationale", "")
            remediation = verdict.get("remediation", "")
            source = "llm"
        else:                                     # fallback to heuristic if LLM unavailable
            is_vuln = cand.heuristic_vulnerable
            confidence = 0.6 if is_vuln else 0.4
            rationale = "Heuristic oracle (LLM verification unavailable)."
            remediation = ""
            source = "heuristic"

        print(f"  {cand.gid:9} {cand.owasp:55} "
              f"heuristic={cand.heuristic_vulnerable!s:5} verdict={is_vuln!s:5} "
              f"conf={confidence:.2f} [{source}]")

        if is_vuln:
            findings.append({
                "gid": cand.gid,
                "name": cand.name,
                "owasp": cand.owasp,
                "endpoint": cand.endpoint,
                "paths": [cand.endpoint],
                "risk": 3,
                "confidence": round(confidence, 2),
                "rationale": rationale,
                "remediation": remediation,
                "verdict_source": source,
                "vulnerable": True,
            })
    duration = time.time() - started
    return {
        "mode": mode,
        "base_url": base_url,
        "model": model or DEFAULT_MODEL,
        "llm_enabled": llm.enabled,
        "duration_seconds": round(duration, 2),
        "n_candidates": len(candidates),
        "n_findings": len(findings),
        "findings": findings,
    }


def write_report(result: dict, out_dir: str) -> None:
    md = [f"# GenAI DAST report — {result['mode']} mode",
          "",
          f"- Target: `{result['base_url']}`",
          f"- Model: `{result['model']}` (LLM {'on' if result['llm_enabled'] else 'off'})",
          f"- Duration: {result['duration_seconds']} s",
          f"- Confirmed findings: **{result['n_findings']}** of {result['n_candidates']} tested",
          "",
          "| Ground-truth | OWASP | Confidence | Source |",
          "|--------------|-------|-----------|--------|"]
    for f in result["findings"]:
        md.append(f"| {f['gid']} {f['name']} | {f['owasp']} | {f['confidence']} | {f['verdict_source']} |")
    md.append("")
    for f in result["findings"]:
        md.append(f"### {f['gid']} — {f['name']}")
        md.append(f"**OWASP:** {f['owasp']}  ")
        md.append(f"**Endpoint:** `{f['endpoint']}`  ")
        md.append(f"**Why:** {f['rationale']}  ")
        if f["remediation"]:
            md.append(f"**Remediation:** {f['remediation']}")
        md.append("")
    with open(os.path.join(out_dir, "report.md"), "w") as fh:
        fh.write("\n".join(md))


def main() -> None:
    ap = argparse.ArgumentParser(description="GenAI DAST scan for OWASP API Top 10")
    ap.add_argument("--target", required=True, help="base URL or OpenAPI URL of the target")
    ap.add_argument("--mode", default="vulnerable", choices=["vulnerable", "secure"])
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("--model", default=None, help=f"OpenAI model (default {DEFAULT_MODEL})")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    print(f"==> GenAI DAST scan [{args.mode}] against {args.target}")
    result = run_scan(args.target, args.mode, args.model)

    with open(os.path.join(args.out, "findings.json"), "w") as fh:
        json.dump(result["findings"], fh, indent=2)
    with open(os.path.join(args.out, "run-meta.json"), "w") as fh:
        json.dump({k: v for k, v in result.items() if k != "findings"}, fh, indent=2)
    write_report(result, args.out)

    print(f"==> {result['n_findings']} findings in {result['duration_seconds']}s -> {args.out}")


if __name__ == "__main__":
    main()
