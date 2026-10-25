import importlib.util
from pathlib import Path
from datetime import date
import unittest

spec = importlib.util.spec_from_file_location("identity_review", Path(__file__).with_name("review.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Tests(unittest.TestCase):
    def test_unprotected_admin(self):
        findings = mod.review(mod.SAMPLE, today=date(2026, 2, 1))
        self.assertTrue(any(f["finding"] == "privileged_without_mfa" for f in findings))

    def test_disabled_account_ignored(self):
        findings = mod.review(mod.SAMPLE, today=date(2026, 2, 1))
        self.assertFalse(any(f["account"] == "lab-former-003" for f in findings))

    def test_multiple_actual_privileged_roles(self):
        account = {"id": "lab-multi", "active": True,
                   "roles": ["Global Administrator", "Groups Administrator", "Reader"],
                   "mfa": True, "last_login": "2026-01-01"}
        alerts = mod.review([account], today=date(2026, 1, 2))
        self.assertEqual([f["finding"] for f in alerts], ["multiple_privileged_roles"])

    def test_three_reader_roles_not_marked_as_privileged(self):
        account = {"id": "lab-read", "active": True,
                   "roles": ["Reader", "Reports Reader", "Directory Reader"],
                   "mfa": True, "last_login": "2026-01-01"}
        self.assertEqual(mod.review([account], today=date(2026, 1, 2)), [])

    def test_duplicate_account_ids_fail(self):
        with self.assertRaises(ValueError):
            mod.review([mod.SAMPLE[0], mod.SAMPLE[0]], today=date(2026, 2, 1))

    def test_future_date_rejected(self):
        with self.assertRaises(ValueError):
            mod.review(mod.SAMPLE, today=date(2024, 1, 1))


if __name__ == "__main__":
    unittest.main()
