import importlib.util
from pathlib import Path
import tempfile
import unittest

p = Path(__file__).with_name("monitor.py")
spec = importlib.util.spec_from_file_location("file_monitor", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Tests(unittest.TestCase):
    def test_file_modifications(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("original")
            before = mod.inventory(tmp)
            path.write_text("changed")
            after = mod.inventory(tmp)
            self.assertEqual(mod.compare(before, after)["modified"], ["sample.txt"])

    def test_added_and_deleted(self):
        self.assertEqual(mod.compare({"old": "1"}, {"new": "2"}),
                         {"added": ["new"], "deleted": ["old"], "modified": []})


if __name__ == "__main__":
    unittest.main()
