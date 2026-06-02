#!/usr/bin/env python3
"""
score.py — score a DAST tool's findings against the VAMPI ground truth.

Computes recall, precision, F1 and false-positive rate for the OWASP API
Security Top 10 (2023), used to compare the OWASP ZAP baseline with the GenAI
framework (Chapter 4 of the thesis).

Methodology
-----------
The oracle is ground_truth/vampi_ground_truth.yaml: a fixed set of N
vulnerability *instances*, each = (endpoint, method, OWASP category), with flags
for whether the instance exists in vulnerable vs secure mode.

A ground-truth instance counts as DETECTED (true positive) when the tool emits at
least one finding that (a) maps to the same OWASP category (via the mapping
tables below) and (b) targets the same endpoint path. Security findings that map
to an OWASP category but match no present ground-truth instance are FALSE
POSITIVES. Header/hygiene/informational findings are bucketed separately as
"non-Top10 noise" and reported but excluded from precision/recall (configurable
with --include-noise).

    recall    = TP / (TP + FN)
    precision = TP / (TP + FP)
    F1        = 2*P*R / (P + R)
    FPR proxy = FP raised against the secure instance (control)

Usage
-----
    python3 score.py --tool zap --mode vulnerable <zap_report.json>
    python3 score.py --tool zap --mode secure     <zap_report.json>
    python3 score.py --tool framework --mode vulnerable <framework_findings.json>
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
GT_PATH = os.path.join(HERE, "..", "ground_truth", "vampi_ground_truth.yaml")

# --- OWASP API Top 10 (2023) canonical keys -------------------------------
API1 = "API1:2023 Broken Object Level Authorization"
API2 = "API2:2023 Broken Authentication"
API3 = "API3:2023 Broken Object Property Level Authorization"
API4 = "API4:2023 Unrestricted Resource Consumption"
API5 = "API5:2023 Broken Function Level Authorization"
API8 = "API8:2023 Security Misconfiguration"
API9 = "API9:2023 Improper Inventory Management"

# --- ZAP alert -> OWASP category mapping ----------------------------------
# Keyed by ZAP plugin id. Anything not listed and not in NOISE_PLUGINS is
# treated as an unmapped security finding (counts toward FP if Low+).
ZAP_PLUGIN_TO_OWASP = {
    "40018": API8,   # SQL Injection            -> injection / misconfiguration
    "40019": API8,   # SQL Injection - MySQL
    "40020": API8,   # SQL Injection - Hypersonic
    "40021": API8,   # SQL Injection - Oracle
    "40022": API8,   # SQL Injection - PostgreSQL
    "40024": API8,   # SQL Injection - SQLite
    "90019": API8,   # Server Side Code Injection
    "90020": API8,   # Remote OS Command Injection
    "40012": API8,   # Cross Site Scripting (Reflected)
    "40014": API8,   # Cross Site Scripting (Persistent)
    "6":     API9,   # Path Traversal / directory browsing
    "10045": API9,   # Source Code Disclosure
    "40035": API9,   # Hidden File Found
}

# ZAP plugin ids that are header-hygiene / informational noise (not a concrete
# exploitable API Top 10 vulnerability). Reported separately.
NOISE_PLUGINS = {
    "10021",  # X-Content-Type-Options Header Missing
    "10036",  # Server Leaks Version Information
    "10037",  # Server Leaks Info via X-Powered-By
    "10049",  # Storable/Non-Storable Content
    "10063",  # Permissions Policy Header Not Set
    "10096",  # Timestamp Disclosure
    "10111",  # Authentication Request Identified
    "90004",  # Cross-Origin-Resource-Policy Header Missing
    "90005",  # Sec-Fetch headers
    "100000", # A Client Error response code was returned
    "10020",  # Anti-clickjacking / X-Frame-Options
    "10038",  # CSP header not set
    "10054",  # Cookie without SameSite
    "10094",  # Base64 disclosure
}


def load_ground_truth():
    """Tiny YAML reader for the fixed-shape ground-truth file (no PyYAML dep)."""
    items, cur = [], None
    with open(GT_PATH) as fh:
        in_vulns = False
        for raw in fh:
            line = raw.rstrip("\n")
            if line.strip().startswith("#") or not line.strip():
                continue
            if line.startswith("vulnerabilities:"):
                in_vulns = True
                continue
            if in_vulns and re.match(r"^[a-z_]+:", line):  # left a top-level block
                in_vulns = False
            if not in_vulns:
                continue
            m = re.match(r"^\s*-\s+id:\s*(.+)$", line)
            if m:
                if cur:
                    items.append(cur)
                cur = {"id": m.group(1).strip()}
                continue
            m = re.match(r"^\s+([a-z_]+):\s*(.*)$", line)
            if m and cur is not None:
                k, v = m.group(1), m.group(2).strip()
                if v.startswith('"'):                 # quoted: take inside quotes
                    v = v[1:].split('"', 1)[0]
                else:                                  # bare: drop inline comment
                    v = v.split(" #", 1)[0].strip().strip('"')
                if k in ("present_when_vulnerable", "present_when_secure"):
                    cur[k] = v.lower().startswith("true")
                elif k in ("name", "endpoint", "method", "owasp", "detail"):
                    cur[k] = v
    if cur:
        items.append(cur)
    return items


def path_matches(gt_endpoint, finding_path):
    """Match an OpenAPI templated path (/users/v1/{username}) against a concrete
    finding path (/users/v1/name1). Path params match any single segment."""
    if not finding_path:
        return False
    fp = finding_path.split("?")[0].rstrip("/")
    gt = gt_endpoint.rstrip("/")
    gt_re = "^" + re.sub(r"\{[^/]+\}", r"[^/]+", re.escape(gt).replace(r"\{", "{").replace(r"\}", "}")) + "$"
    # re.escape escaped the braces; rebuild a clean regex instead:
    gt_re = "^" + re.sub(r"\{[^}]+\}", r"[^/]+", gt) + "/?$"
    return re.match(gt_re, fp) is not None


def parse_zap(report_path, base_hosts=("vampi-vulnerable:5000", "vampi-secure:5000")):
    """Return list of findings: {plugin, name, owasp|None, noise, risk, paths[]}."""
    d = json.load(open(report_path))
    findings = []
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            plugin = str(a.get("pluginid"))
            paths = []
            for inst in a.get("instances", []):
                uri = inst.get("uri", "")
                p = uri
                for h in base_hosts:
                    p = p.replace("http://" + h, "")
                p = re.sub(r"^https?://[^/]+", "", p)
                paths.append(p or "/")
            findings.append({
                "plugin": plugin,
                "name": a.get("alert"),
                "risk": int(a.get("riskcode", 0)),
                "owasp": ZAP_PLUGIN_TO_OWASP.get(plugin),
                "noise": plugin in NOISE_PLUGINS,
                "paths": sorted(set(paths)),
            })
    return findings


def score(findings, gt, mode, include_noise=False):
    present_key = "present_when_vulnerable" if mode == "vulnerable" else "present_when_secure"
    gt_present = [g for g in gt if g.get(present_key)]

    # True positives / false negatives over present ground-truth instances.
    detected, missed = [], []
    for g in gt_present:
        hit = None
        for f in findings:
            if f["owasp"] and f["owasp"] == g["owasp"]:
                if any(path_matches(g["endpoint"], p) for p in f["paths"]):
                    hit = f
                    break
        (detected if hit else missed).append(g)

    # False positives: mapped security findings that match no present GT instance.
    fp = []
    for f in findings:
        if f["noise"] and not include_noise:
            continue
        if not f["owasp"]:
            # unmapped, non-noise security finding
            if f["risk"] >= 1 and include_noise:
                fp.append(f)
            continue
        matched = any(
            f["owasp"] == g["owasp"] and any(path_matches(g["endpoint"], p) for p in f["paths"])
            for g in gt_present
        )
        if not matched:
            fp.append(f)

    TP, FN, FP = len(detected), len(missed), len(fp)
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    precision = TP / (TP + FP) if (TP + FP) else (1.0 if TP else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    noise = [f for f in findings if f["noise"]]
    return {
        "mode": mode,
        "present_instances": len(gt_present),
        "TP": TP, "FN": FN, "FP": FP,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "f1": round(f1, 3),
        "noise_findings": len(noise),
        "detected": [g["id"] + " " + g["owasp"] for g in detected],
        "missed": [g["id"] + " " + g["owasp"] for g in missed],
        "false_positives": [f["name"] for f in fp],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="tool findings JSON")
    ap.add_argument("--tool", default="zap", choices=["zap", "framework"])
    ap.add_argument("--mode", required=True, choices=["vulnerable", "secure"])
    ap.add_argument("--include-noise", action="store_true")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()

    gt = load_ground_truth()
    if args.tool == "zap":
        findings = parse_zap(args.report)
    else:
        # framework findings already in normalized form: [{owasp, paths[], risk, name, noise?}]
        findings = json.load(open(args.report))
        for f in findings:
            f.setdefault("noise", False)
            f.setdefault("risk", 2)
            f.setdefault("paths", [f.get("endpoint", "")])

    result = score(findings, gt, args.mode, include_noise=args.include_noise)
    result["tool"] = args.tool

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\n=== {args.tool.upper()} vs VAMPI ground truth [{args.mode}] ===")
    print(f"  present instances : {result['present_instances']}")
    print(f"  TP / FN / FP      : {result['TP']} / {result['FN']} / {result['FP']}")
    print(f"  recall            : {result['recall']}")
    print(f"  precision         : {result['precision']}")
    print(f"  F1                : {result['f1']}")
    print(f"  non-Top10 noise   : {result['noise_findings']} findings")
    print(f"  detected          : {result['detected'] or '-'}")
    print(f"  missed            : {result['missed'] or '-'}")
    print(f"  false positives   : {result['false_positives'] or '-'}")


if __name__ == "__main__":
    main()
