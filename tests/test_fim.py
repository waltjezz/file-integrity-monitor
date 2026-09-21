import tempfile
import unittest
from pathlib import Path

from fim import compare, create_baseline, sha256_file


class FileIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "monitored"
        self.data.mkdir()
        (self.data / "unchanged.txt").write_text("hello", encoding="utf-8")
        (self.data / "changed.txt").write_text("first", encoding="utf-8")
        (self.data / "removed.txt").write_text("remove", encoding="utf-8")
        self.manifest = self.root / "baseline.json"

    def test_sha256_known_value(self):
        self.assertEqual(
            sha256_file(self.data / "unchanged.txt"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_no_changes(self):
        self.assertEqual(create_baseline(self.data, self.manifest, []), 3)
        self.assertEqual(compare(self.data, self.manifest),
                         {"added": [], "removed": [], "modified": []})

    def test_detects_three_change_types(self):
        create_baseline(self.data, self.manifest, [])
        (self.data / "changed.txt").write_text("second", encoding="utf-8")
        (self.data / "removed.txt").unlink()
        (self.data / "new.txt").write_text("new", encoding="utf-8")
        self.assertEqual(compare(self.data, self.manifest), {
            "added": ["new.txt"], "removed": ["removed.txt"],
            "modified": ["changed.txt"],
        })

    def test_exclude_pattern(self):
        (self.data / "debug.log").write_text("ignored", encoding="utf-8")
        self.assertEqual(create_baseline(self.data, self.manifest, ["*.log"]), 3)
        (self.data / "debug.log").write_text("changed", encoding="utf-8")
        self.assertEqual(compare(self.data, self.manifest),
                         {"added": [], "removed": [], "modified": []})

    def test_manifest_inside_monitored_folder(self):
        manifest = self.data / "baseline.json"
        self.assertEqual(create_baseline(self.data, manifest, []), 3)
        self.assertEqual(compare(self.data, manifest),
                         {"added": [], "removed": [], "modified": []})


if __name__ == "__main__":
    unittest.main()
