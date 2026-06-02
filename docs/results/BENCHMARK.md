# Benchmark results — GenAI framework vs OWASP ZAP

Target: **VAMPI** (erev0s/VAmPI) running in **vulnerable mode** (`vulnerable=1`) on
port 5002. Oracle: `ground_truth/vampi_ground_truth.yaml` (9 code-verified OWASP
API Security Top 10 (2023) instances).

## Detection performance

| Tool | Instances | TP | FN | FP | Recall | Precision | F1 | Non-Top10 noise |
|------|-----------|----|----|----|--------|-----------|----|-----------------|
| OWASP ZAP (api-scan) | 9 | 0 | 9 | 0 | 0.00 | 0.00 | 0.00 | 7 |
| **GenAI framework** | 9 | 9 | 0 | 0 | **1.00** | **1.00** | **1.00** | 0 |

The out-of-the-box ZAP API scan detected **none** of VAMPI's API Top 10 logic
flaws — only HTTP header-hygiene findings (missing `X-Content-Type-Options`,
server version disclosure, CORP header), which map to no ground-truth instance.
The GenAI framework detected **all nine** instances with **zero false positives**
(every reported finding corresponds to a real vulnerability), giving perfect
precision, recall and F1.

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
| OWASP ZAP | ~25–65 s |
| GenAI framework (gpt-4o) | ~230 s |

The GenAI framework trades a higher per-run cost (LLM latency: 4 payload-generation
+ 9 verification calls) for materially higher detection. Both run unattended inside
GitHub Actions on every push, with no manual tuning.

> Numbers above are reproduced on every push by the `API Security Scan` GitHub
> Actions workflow (artifacts + job-summary table). Raw evidence:
> `docs/results/framework-vuln-{findings,meta}.json`.
