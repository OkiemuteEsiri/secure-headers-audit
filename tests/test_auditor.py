import unittest
from src.auditor import audit, metrics
from src.models import Target
from src.reporting import markdown_report


def target(headers=None, tls=True, owner="owner"):
    return Target("lab", "https://lab.example.test", {k.lower(): v for k, v in (headers or {}).items()}, tls, owner)


class AuditTests(unittest.TestCase):
    def test_missing_csp_high(self):
        self.assertTrue(any(f.control_id == "HDR-001" and f.severity == "High" for f in audit(target())))

    def test_good_csp_not_flagged(self):
        fs = audit(target({"Content-Security-Policy": "default-src 'self'"}))
        self.assertFalse(any(f.control_id in {"HDR-001", "HDR-002"} for f in fs))

    def test_permissive_csp(self):
        fs = audit(target({"Content-Security-Policy": "default-src *"}))
        self.assertTrue(any(f.control_id == "HDR-002" for f in fs))

    def test_hsts_only_expected_for_tls(self):
        self.assertFalse(any(f.control_id == "HDR-003" for f in audit(target(tls=False))))

    def test_nosniff_good(self):
        fs = audit(target({"X-Content-Type-Options": "nosniff"}))
        self.assertFalse(any(f.control_id == "HDR-004" for f in fs))

    def test_permissive_referrer(self):
        fs = audit(target({"Referrer-Policy": "unsafe-url"}))
        self.assertTrue(any(f.control_id == "HDR-005" for f in fs))

    def test_missing_owner(self):
        self.assertTrue(any(f.control_id == "GOV-001" for f in audit(target(owner=""))))

    def test_scores_bounded(self):
        self.assertTrue(all(0 <= f.score <= 100 for f in audit(target())))

    def test_metrics(self):
        fs = audit(target())
        self.assertEqual(metrics(fs)["findings"], len(fs))

    def test_report_states_offline(self):
        self.assertIn("No network requests were performed", markdown_report([]))


if __name__ == "__main__": unittest.main()
