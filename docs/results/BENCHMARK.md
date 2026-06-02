# Benchmark results — GenAI framework vs OWASP ZAP

Target: **VAMPI** (erev0s/VAmPI) running in **vulnerable mode** (`vulnerable=1`) on
port 5002. Oracle: `ground_truth/vampi_ground_truth.yaml` (9 code-verified OWASP
API Security Top 10 (2023) instances).

The ZAP baseline is **tuned**, not default: it authenticates with a real JWT
injected into every request and runs every active-scan rule at HIGH attack
strength / LOW alert threshold — an expert-configured baseline.

## Detection performance

| Tool | Instances | TP | FN | FP | Recall | Precision | F1 | Non-Top10 noise |
|------|-----------|----|----|----|--------|-----------|----|-----------------|
| OWASP ZAP (tuned) | 9 | 0 | 9 | 1 | 0.00 | 0.00 | 0.00 | 13 |
| **GenAI framework** | 9 | 9 | 0 | 0 | **1.00** | **1.00** | **1.00** | 0 |

Even tuned and authenticated, the ZAP scan detected **none** of VAMPI's nine API
Top 10 flaws. Its payloads reached the authenticated endpoints and even provoked
HTTP 500s there, but its active-scan rules confirmed nothing — its SQL-injection
scanner, for example, ran against the injectable endpoint yet raised no alert.
ZAP's output was 13 low/informational findings (missing security headers, server
version disclosure, verbose error/debug disclosure) plus **one false-positive
medium "Buffer Overflow"** alert — none a real OWASP API Top 10 vulnerability. The
GenAI framework detected **all nine** instances with **zero false positives**,
giving perfect precision, recall and F1.

## Per-instance detection

| Ground truth | OWASP API Top 10 (2023) | ZAP | Framework |
|--------------|--------------------------|-----|-----------|
| VAMPI-01 SQL injection (user lookup) | API8 Security Misconfiguration | ✗ | ✓ |
| VAMPI-02 BOLA (book secret) | API1 Broken Object Level Authorization | ✗ | ✓ |
| VAMPI-03 user/password enumeration | API2 Broken Authentication | ✗ | ✓ |
| VAMPI-04 weak/static JWT key | API2 Broken Authentication | ✗ | ✓ |
| VAMPI-05 mass assignment (admin) | API3 Broken Object Property Level Authorization | ✗ | ✓ |
| VAMPI-06 excessive data exposure (debug) | API3 Broken Object Property Level Authorization | ✗ | ✓ |
| VAMPI-07 BFLA (change other's password) | API5 Broken Function Level Authorization | ✗ | ✓ |
| VAMPI-08 Regex DoS (email) | API4 Unrestricted Resource Consumption | ✗ | ✓ |
| VAMPI-09 no rate limiting (login) | API4 Unrestricted Resource Consumption | ✗ | ✓ |

## CI overhead (wall-clock scan time)

| Tool | Scan time |
|------|-----------|
| OWASP ZAP (tuned) | ~80 s |
| GenAI framework (gpt-4o) | ~230 s |

The GenAI framework trades a higher per-run cost (LLM latency: 4 payload-generation
+ 9 verification calls) for materially higher detection. Both run unattended inside
GitHub Actions on every push, with no manual tuning.

> Numbers above are reproduced on every push by the `API Security Scan` GitHub
> Actions workflow (artifacts + job-summary table). Raw evidence:
> `docs/results/framework-vuln-{findings,meta}.json`.
