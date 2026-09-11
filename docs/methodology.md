# Secure Header Audit Methodology

## Scope
This lab evaluates response-header metadata supplied as JSON. It deliberately performs no HTTP requests, crawling, exploitation or active testing.

## Controls
The initial control catalog assesses Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and remediation ownership. Findings include evidence, rationale, remediation and explicit revalidation criteria.

## Risk interpretation
Scores are deterministic prioritization aids, not CVSS scores and not proof of exploitability. Missing CSP is treated as higher priority because CSP is an important defense-in-depth control against classes of injected active content. HSTS is assessed only for targets declared HTTPS. Lower-severity headers remain valuable hardening controls but should be prioritized in application context.

## CSP nuance
The auditor does not claim that a CSP automatically prevents XSS. It flags absence and obviously broad source patterns as review conditions. A production CSP should be application-specific, regression-tested and preferably developed with reporting/monitoring before enforcement.

## Validation workflow
1. Confirm the response and application path in scope.
2. Validate the finding against intended application behavior.
3. Implement the control in a controlled environment.
4. Regression-test authentication, third-party integrations and browser features.
5. Re-audit the supplied response metadata.
6. Capture evidence and close only after successful validation.

## Limitations
Header posture is only one part of web security. This project does not test application authorization, injection, session behavior, business logic, TLS cryptography or server vulnerabilities. Browser support and application requirements can change the appropriate policy.
