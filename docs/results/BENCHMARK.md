# Benchmark results — GenAI framework vs OWASP ZAP

Target: **VAMPI** (erev0s/VAmPI), dual-mode (`vulnerable=1` on :5002, `vulnerable=0`
on :5001). Oracle: `ground_truth/vampi_ground_truth.yaml` (9 code-verified OWASP
API Top 10 (2023) instances; 3 of them persist in secure mode).

## Detection performance

| Tool | Mode | Instances | TP | FN | FP | Recall | Precision | F1 | Non-Top10 noise |
|------|------|-----------|----|----|----|--------|-----------|----|-----------------|
| OWASP ZAP (api-scan) | vulnerable | 9 | 0 | 9 | 0 | 0.00 | 0.00 | 0.00 | 7 |
| OWASP ZAP (api-scan) | secure | 3 | 0 | 3 | 0 | 0.00 | 0.00 | 0.00 | 7 |
| **GenAI framework** | vulnerable | 9 | 9 | 0 | 0 | **1.00** | **1.00** | **1.00** | 0 |
| **GenAI framework** | secure | 3 | 3 | 0 | 0 | **1.00** | **1.00** | **1.00** | 0 |

The out-of-the-box ZAP API scan detected **none** of VAMPI's API Top 10 logic
flaws — only HTTP header-hygiene findings (missing `X-Content-Type-Options`,
server version disclosure, CORP header), which map to no ground-truth instance.
The GenAI framework detected **all** present instances in both modes with **zero
false positives** (it correctly stayed silent on the six vulnerabilities that the
secure build fixes).

## Per-instance detection (vulnerable mode)

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

| Tool | Mode | Scan time |
|------|------|-----------|
| OWASP ZAP | vulnerable | ~25–63 s |
| OWASP ZAP | secure | ~25 s |
| GenAI framework (gpt-4o) | vulnerable | ~230 s |
| GenAI framework (gpt-4o) | secure | ~210 s |

The GenAI framework trades a higher per-run cost (LLM latency: 4 payload-generation
+ 9 verification calls) for materially higher detection. Both run unattended inside
GitHub Actions on every push, with no manual tuning.

> Numbers above are from local runs; the authoritative figures are reproduced on
> every push by the `API Security Scan` GitHub Actions workflow (artifacts +
> job-summary table). Raw evidence: `docs/results/framework-*-{findings,meta}.json`.
