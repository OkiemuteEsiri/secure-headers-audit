# Secure Headers Audit

A defensive Web Application Security engineering project that evaluates supplied HTTP response-header metadata against a practical browser-security baseline. The implementation is deliberately **offline**: it analyzes synthetic JSON configuration and does not crawl, scan or send requests to websites.

## Problem statement
HTTP security headers are defense-in-depth controls, but simply checking whether a header exists can produce misleading results. This project models a more disciplined workflow: normalize evidence, evaluate control semantics, prioritize weaknesses, document rationale, recommend remediation and define how the fix should be revalidated.

## Architecture

```text
Synthetic target/header metadata
            |
            v
      strict JSON ingestion
            |
            v
        Target model
            |
            v
     control audit engine
            |
            v
 Finding + score + evidence
            |
            v
 remediation / validation report
```

## Current control catalog
| Control | Review condition |
|---|---|
| Content-Security-Policy | Missing or obviously permissive policy |
| Strict-Transport-Security | Missing on a declared HTTPS target |
| X-Content-Type-Options | Missing or not `nosniff` |
| Referrer-Policy | Missing or permissive policy |
| Permissions-Policy | Missing explicit browser-feature policy |
| Governance | Missing accountable remediation owner |

## CSP handling
CSP is treated carefully. The tool does **not** claim that CSP alone prevents XSS. It identifies missing or clearly broad policies for review. Production CSP design must reflect actual application dependencies and should be regression-tested before enforcement.

## Repository structure

```text
src/
  models.py
  auditor.py
  io.py
  reporting.py
  cli.py
data/
  synthetic_targets.json
tests/
  test_auditor.py
docs/
  methodology.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Usage
Python 3.12+; no third-party dependencies.

```bash
python -m src.cli data/synthetic_targets.json --output assessment.md
python -m unittest discover -s tests -v
```

## Engineering features
The project includes immutable assessment models, normalized case-insensitive header names, fail-closed JSON validation, deterministic control IDs, bounded risk scores, evidence-backed findings, remediation guidance, explicit validation criteria, portfolio metrics, a Markdown reporting layer, ten unit tests and least-privilege CI.

## Risk model
The 0–100 values are deterministic prioritization scores—not CVSS and not exploitability probabilities. Header findings must be interpreted with application context. Missing defense-in-depth controls can increase exposure, but they do not by themselves prove an exploitable vulnerability.

## Remediation lifecycle
`identify -> validate -> design fix -> test -> deploy under change control -> re-audit -> capture closure evidence`

This makes the project useful not only for finding configuration gaps but also for demonstrating remediation assurance.

## Skills demonstrated
Web application security, secure configuration review, Python security automation, defensive control engineering, risk communication, evidence governance, remediation validation, unit testing and CI/CD.

## CI
GitHub Actions uses read-only repository permissions and performs Python compilation, the unit-test suite and an offline CLI smoke test.

## Limitations
This is not an active scanner and does not make HTTP requests. It does not test XSS, SQL injection, authentication, authorization, session management, TLS cipher configuration, business logic or server vulnerabilities. Browser support and application requirements must be considered before production policy changes.

## Roadmap
- Add configurable policy profiles for browser applications and APIs.
- Add richer CSP directive analysis.
- Add COOP/COEP/CORP review where context supports them.
- Add JSON and CSV findings export.
- Add trend comparison for remediation validation.
- Add optional integration adapters that remain disabled by default.

## Safety
All bundled targets and header values are synthetic. The repository is intended for authorized defensive security engineering and secure-configuration education.
