from .auditor import metrics
from .models import Finding


def markdown_report(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = ["# Secure Headers Assessment", "", "> Offline assessment of supplied synthetic response metadata. No network requests were performed.", "",
             "## Executive metrics", "", f"- Findings: **{m['findings']}**", f"- High/Medium: **{m['high_medium']}**", f"- Highest score: **{m['highest_score']}**", "", "## Findings", ""]
    for f in findings:
        lines += [f"### {f.severity} — {f.control_id}: {f.title}", "", f"- Target: `{f.target}`", f"- Score: **{f.score}/100**", f"- Evidence: `{f.evidence}`", f"- References: {', '.join(f.references)}", "",
                  f"**Rationale:** {f.rationale}", "", f"**Remediation:** {f.remediation}", "", f"**Validation:** {f.validation}", ""]
    return "\n".join(lines)
