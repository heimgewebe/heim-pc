"""Source-level guard tests for the NixOS Grabowski retention producer."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "nixos/system/modules/grabowski-production.nix"
PATCHED_TOOL_SHA256 = "32d061ec9b405f20ae6a4456ef53b5c1dbdaa8c1f66606bb23096a5230202cb7"


class GrabowskiRetentionTimerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_retention_is_off_by_default_and_tied_to_canonical_operator(self) -> None:
        self.assertIn("retentionEnable = lib.mkEnableOption", self.source)
        self.assertIn("retentionAdmit = admit && cfg.retentionEnable;", self.source)
        self.assertIn("assertion = !cfg.retentionEnable || admit;", self.source)
        self.assertIn("systemd.user.services.grabowski-runtime-retention = lib.mkIf retentionAdmit", self.source)
        self.assertIn("systemd.user.timers.grabowski-runtime-retention = lib.mkIf retentionAdmit", self.source)

    def test_reviewed_immutable_tool_hash_precedes_every_effect(self) -> None:
        self.assertIn(f'retentionToolSha256 = "{PATCHED_TOOL_SHA256}";', self.source)
        self.assertIn('retentionTool = "${cfg.operatorPackage}/share/grabowski/tools/maintain_runtime_state.py";', self.source)
        start = self.source.index("systemd.user.services.grabowski-runtime-retention")
        stop = self.source.index("systemd.user.timers.grabowski-runtime-retention")
        service = self.source[start:stop]
        self.assertLess(service.index("-I -B -c"), service.index("--provision-receipt-root"))
        self.assertLess(service.index("--provision-receipt-root"), service.index("--periodic-apply"))
        self.assertIn("${cfg.operatorPackage}/bin/python3", service)
        self.assertNotIn("pkgs.writeText", self.source)
        self.assertNotIn(".venv/bin/python", service)
        self.assertNotIn("--worktree-hygiene-repo", service)

    def test_retention_is_bounded_private_and_unprivileged(self) -> None:
        start = self.source.index("systemd.user.services.grabowski-runtime-retention")
        stop = self.source.index("systemd.user.timers.grabowski-runtime-retention")
        service = self.source[start:stop]
        for required in (
            'unitConfig.ConditionUser = "alex";',
            '--minimum-job-age-seconds 86400 --max-archive-jobs 128',
            'NoNewPrivileges = true;',
            'ProtectSystem = "strict";',
            'ProtectHome = "read-only";',
            'ReadWritePaths = [ "%h/.local/state/grabowski" ];',
            'UMask = "0077";',
            'MemoryMax = "512M";',
            'TasksMax = 50;',
        ):
            with self.subTest(required=required):
                self.assertIn(required, service)
        self.assertNotIn("User = \"root\"", service)
        self.assertNotIn("SourcePath", service)

    def test_single_five_minute_systemd_producer(self) -> None:
        timer = self.source.split("systemd.user.timers.grabowski-runtime-retention", 1)[1]
        self.assertIn('wantedBy = [ "timers.target" ];', timer)
        self.assertIn('OnUnitActiveSec = "5min";', timer)
        self.assertIn('OnBootSec = "3min";', timer)
        self.assertIn('Unit = "grabowski-runtime-retention.service";', timer)
        self.assertIn('Persistent = true;', timer)


if __name__ == "__main__":
    unittest.main()