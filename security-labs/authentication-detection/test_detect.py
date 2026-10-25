"""Regression tests for synthetic authentication anomaly detection."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("auth_detect", Path(__file__).with_name("detect.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def event(minute, user, ip="192.0.2.10", result="failure"):
    return {"timestamp": f"2026-01-01T12:{minute:02d}:00Z",
            "user": user, "ip": ip, "result": result}


class DetectionTests(unittest.TestCase):
    def test_three_distinct_users_trigger_spray_hypothesis(self):
        alerts = mod.analyze([event(1, "a"), event(2, "b"), event(3, "c")])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "possible_password_spray")
        self.assertEqual(alerts[0]["mitre_attack"], "T1110.003")

    def test_successful_signins_are_not_counted(self):
        alerts = mod.analyze([event(1, "a"), event(2, "b", result="success"), event(3, "c")])
        self.assertEqual(alerts, [])

    def test_different_sources_do_not_merge(self):
        alerts = mod.analyze([event(1, "a"), event(2, "b", "192.0.2.11"), event(3, "c")])
        self.assertEqual(alerts, [])

    def test_single_identity_failure_burst(self):
        alerts = mod.analyze([event(i, "a", f"192.0.2.{i+10}") for i in range(5)])
        self.assertEqual([x["rule"] for x in alerts], ["repeated_authentication_failures"])

    def test_suppress_duplicate_spray_alerts_in_window(self):
        alerts = mod.analyze([event(i, f"user{i}") for i in range(7)])
        self.assertEqual(len([x for x in alerts if x["rule"] == "possible_password_spray"]), 1)

    def test_events_outside_window_do_not_trigger(self):
        alerts = mod.analyze([event(0, "a"), event(11, "b"), event(23, "c")])
        self.assertEqual(alerts, [])

    def test_out_of_order_events_are_sorted(self):
        alerts = mod.analyze([event(3, "c"), event(1, "a"), event(2, "b")])
        self.assertEqual(len(alerts), 1)

    def test_missing_timezone_fails_closed(self):
        with self.assertRaises(ValueError):
            mod.analyze([{**event(1, "a"), "timestamp": "2026-01-01T12:01:00"}])

    def test_invalid_threshold_fails_closed(self):
        with self.assertRaises(ValueError):
            mod.analyze(mod.SAMPLE, min_users=0)

    def test_invalid_result_fails_closed(self):
        with self.assertRaises(ValueError):
            mod.analyze([{**event(1, "a"), "result": "unknown"}])


if __name__ == "__main__":
    unittest.main()
