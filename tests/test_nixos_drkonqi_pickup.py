"""Regress KDE DrKonqi 6.6.6 startup pickup vs real crash reporting."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "nixos/system/modules/desktop.nix"
PATCH = ROOT / "nixos/system/modules/patches/drkonqi-6.6.6-pickup-at-log-end.patch"


class DrkonqiPickupTest(unittest.TestCase):
    def test_old_crash_pickup_exits_on_journal_end(self):
        patch = PATCH.read_text()
        self.assertIn("if (pickup) {", patch)
        self.assertIn(
            "QObject::connect(&watcher, &CoredumpWatcher::atLogEnd, &app, &QCoreApplication::quit, Qt::QueuedConnection);",
            patch,
        )
        self.assertIn("QObject::connect(&watcher, &CoredumpWatcher::finished", patch)
        self.assertNotIn("SuccessExitStatus=", patch)

    def test_patch_has_correct_old_and_new_line_counts(self):
        lines = PATCH.read_text().splitlines()
        header = next(x for x in lines if x.startswith("@@ "))
        m = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", header)
        self.assertIsNotNone(m)
        old_count = new_count = 0
        for line in lines[lines.index(header) + 1:]:
            if line.startswith(" "):
                old_count += 1
                new_count += 1
            elif line.startswith("-"):
                old_count += 1
            elif line.startswith("+"):
                new_count += 1
            else:
                self.fail(f"Malformed patch line: {line!r}")
        self.assertEqual(old_count, int(m.group(2)))
        self.assertEqual(new_count, int(m.group(4)))

    def test_nixos_only_replaces_pickup_executable(self):
        source = DESKTOP.read_text()
        self.assertIn('pkgs.kdePackages.drkonqi.overrideAttrs', source)
        self.assertIn('drkonqi-6.6.6-pickup-at-log-end.patch', source)
        self.assertIn('systemd.user.services."drkonqi-coredump-pickup"', source)
        self.assertIn('overrideStrategy = "asDropin";', source)
        self.assertIn('drkonqiPickup}/libexec/drkonqi-coredump-processor --settle-first --pickup --uid %U', source)
        self.assertIn('systemd.user.services."drkonqi-coredump-launcher@"', source)


if __name__ == "__main__":
    unittest.main()
