import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).with_name("detect.py")
spec = importlib.util.spec_from_file_location("auth_detect", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Tests(unittest.TestCase):
    def test_detect_spray(self):
        self.assertTrue(any(x["rule"] == "password_spray" for x in mod.analyze(mod.SAMPLE)))

    def test_no_spray_with_unique_sources(self):
        events = [{**e, "ip": f"192.0.2.{i + 1}"} for i, e in enumerate(mod.SAMPLE)]
        self.assertFalse(any(x["rule"] == "password_spray" for x in mod.analyze(events)))

    def test_reject_missing_timezone(self):
        with self.assertRaises(ValueError):
            mod.analyze([{**mod.SAMPLE[0], "timestamp": "2026-01-01T12:00:00"}])


if __name__ == "__main__":
    unittest.main()
