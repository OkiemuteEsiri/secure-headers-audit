from collections import Counter
from .models import Finding, Target


def _finding(cid, title, severity, score, t, evidence, rationale, remediation, validation, refs):
    return Finding(cid, title, severity, score, t.name, evidence, rationale, remediation, validation, tuple(refs))


def audit(t: Target) -> list[Finding]:
    h = t.headers
    out: list[Finding] = []
    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(_finding("HDR-001", "Content-Security-Policy missing", "High", 78, t, "header absent",
            "A CSP can reduce impact from injected active content when designed for the application.",
            "Deploy a tested CSP using restrictive source directives; avoid broad wildcards and unsafe script allowances where feasible.",
            "Confirm the intended CSP is returned and application functionality remains valid.", ["OWASP Secure Headers", "CWE-693"]))
    elif "unsafe-inline" in csp.lower() or "*" in csp:
        out.append(_finding("HDR-002", "Content-Security-Policy is permissive", "Medium", 58, t, csp,
            "Broad CSP source expressions or unsafe-inline reduce policy strength.", "Refine directives using nonces/hashes and explicit trusted origins.",
            "Re-audit the response and regression-test application flows.", ["OWASP Secure Headers", "CWE-693"]))

    if t.tls and "strict-transport-security" not in h:
        out.append(_finding("HDR-003", "HSTS missing on HTTPS target", "Medium", 60, t, "header absent",
            "HSTS instructs supporting browsers to use HTTPS for subsequent requests.",
            "After confirming complete HTTPS support, add an appropriate max-age and evaluate includeSubDomains/preload deliberately.",
            "Verify HSTS on HTTPS responses and test affected subdomains before broader scope.", ["OWASP Secure Headers", "CWE-319"]))

    xcto = h.get("x-content-type-options", "").lower()
    if xcto != "nosniff":
        out.append(_finding("HDR-004", "X-Content-Type-Options missing or weak", "Low", 35, t, xcto or "header absent",
            "nosniff reduces MIME-type interpretation ambiguity in supported browsers.", "Set X-Content-Type-Options: nosniff.",
            "Confirm the exact nosniff value is returned.", ["OWASP Secure Headers", "CWE-693"]))

    rp = h.get("referrer-policy", "").lower()
    if not rp or rp in {"unsafe-url", "no-referrer-when-downgrade"}:
        out.append(_finding("HDR-005", "Referrer-Policy absent or permissive", "Low", 30, t, rp or "header absent",
            "A permissive referrer policy can disclose unnecessary URL context to other origins.",
            "Select a privacy-appropriate policy such as strict-origin-when-cross-origin or stricter after application review.",
            "Confirm cross-origin navigation exposes only the intended referrer data.", ["OWASP Secure Headers"]))

    pp = h.get("permissions-policy", "")
    if not pp:
        out.append(_finding("HDR-006", "Permissions-Policy missing", "Low", 25, t, "header absent",
            "Explicit browser-feature policy reduces unnecessary feature exposure.",
            "Define only features/origins required by the application.", "Verify required browser capabilities still function.", ["OWASP Secure Headers"]))

    if not t.owner:
        out.append(_finding("GOV-001", "Security-header ownership missing", "Low", 20, t, "owner empty",
            "Findings without accountable ownership are harder to remediate and revalidate.", "Assign an application or service owner.",
            "Confirm ownership in the service inventory and remediation ticket.", ["Security governance"]))
    return sorted(out, key=lambda x: x.score, reverse=True)


def metrics(findings: list[Finding]) -> dict:
    c = Counter(f.severity for f in findings)
    return {"findings": len(findings), "high_medium": c["High"] + c["Medium"], "highest_score": max((f.score for f in findings), default=0), "severity_counts": dict(c)}
