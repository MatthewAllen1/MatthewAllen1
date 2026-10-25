import importlib.util
from pathlib import Path
from datetime import date
import unittest

p = Path(__file__).with_name("review.py")
spec = importlib.util.spec_from_file_location("identity_review", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Tests(unittest.TestCase):
    def test_unprotected_admin(self):
        findings = mod.review(mod.SAMPLE, today=date(2026, 2, 1))
        self.assertTrue(any(f["finding"] == "privileged_without_mfa" for f in findings))

    def test_disabled_account_ignored(self):
        findings = mod.review(mod.SAMPLE, today=date(2026, 2, 1))
        self.assertFalse(any(f["account"] == "lab-former-003" for f in findings))


if __name__ == "__main__":
    unittest.main()
