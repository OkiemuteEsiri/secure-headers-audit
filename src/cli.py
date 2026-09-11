import argparse
from pathlib import Path
from .auditor import audit
from .io import load_targets
from .reporting import markdown_report


def main():
    p = argparse.ArgumentParser(description="Audit supplied HTTP security-header metadata offline")
    p.add_argument("input")
    p.add_argument("--output", default="secure-headers-assessment.md")
    a = p.parse_args()
    findings = [f for t in load_targets(a.input) for f in audit(t)]
    Path(a.output).write_text(markdown_report(findings), encoding="utf-8")
    print(f"Wrote {a.output} with {len(findings)} findings")


if __name__ == "__main__": main()
