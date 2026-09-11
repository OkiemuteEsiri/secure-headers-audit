# Example Secure Headers Assessment

> Illustrative assessment based exclusively on synthetic header metadata.

## Executive summary
The synthetic customer portal lacks CSP and HSTS, while the synthetic legacy application has a permissive CSP, lacks HSTS and other defense-in-depth headers, and has no remediation owner. The synthetic API documentation target represents the stronger baseline in the sample.

## Remediation sequence
1. Assign ownership for the legacy application.
2. Design and test CSPs based on actual application dependencies.
3. Enable HSTS only after confirming complete HTTPS readiness and subdomain implications.
4. Apply nosniff, an appropriate Referrer-Policy and a least-functionality Permissions-Policy.
5. Regression-test and re-audit before closure.

## Assurance statement
A clean header audit does not establish that an application is secure. These controls complement authorization testing, secure session management, dependency management, TLS review, input/output controls and application-specific security testing.
