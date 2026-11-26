import subprocess
import unittest
from unittest import mock

from scripts.ci import check_pinned_nix_find_contract as check
from scripts import managed_build
from scripts import nixos_production_install as installer


class PinnedNixMirrorTests(unittest.TestCase):
    canonical = installer.PINNED_NIX_IMAGE_REF
    mirror = "mirror.gcr.io/" + canonical

    @staticmethod
    def ok(stdout=b""):
        return subprocess.CompletedProcess([], 0, stdout, b"")

    @staticmethod
    def error(message=b"toomanyrequests"):
        return subprocess.CompletedProcess([], 1, b"", message)

    def inspect_ok(self):
        return self.ok((managed_build.PINNED_NIX_IMAGE + "\n").encode("ascii"))

    def test_mirror_success_preserves_manifest_and_image_id(self):
        with mock.patch.object(check, "_run", side_effect=[self.ok(), self.inspect_ok()]) as run:
            self.assertEqual(check._pull_pinned_image("docker"), (self.mirror, managed_build.PINNED_NIX_IMAGE))
            self.assertEqual(run.call_args_list, [
                mock.call(["docker", "pull", self.mirror], timeout_seconds=check.PULL_TIMEOUT_SECONDS),
                mock.call(["docker", "image", "inspect", "--format", "{{.Id}}", self.mirror], timeout_seconds=check.COMMAND_TIMEOUT_SECONDS),
            ])

    def test_mirror_failure_uses_same_canonical_digest(self):
        with mock.patch.object(check, "_run", side_effect=[self.error(), self.ok(), self.inspect_ok()]) as run:
            self.assertEqual(check._pull_pinned_image("docker"), (self.canonical, managed_build.PINNED_NIX_IMAGE))
            self.assertEqual(run.call_args_list[1].args[0], ["docker", "pull", self.canonical])
            self.assertEqual(run.call_args_list[2].args[0][-1], self.canonical)

    def test_mirror_timeout_uses_canonical(self):
        timeout = subprocess.TimeoutExpired(["docker", "pull", self.mirror], 300)
        with mock.patch.object(check, "_run", side_effect=[timeout, self.ok(), self.inspect_ok()]):
            self.assertEqual(check._pull_pinned_image("docker")[0], self.canonical)

    def test_both_pull_failures_report_both_sources(self):
        with mock.patch.object(check, "_run", side_effect=[self.error(b"mirror unavailable"), self.error(b"rate limited")]) as run:
            with self.assertRaisesRegex(RuntimeError, "mirror unavailable.*rate limited"):
                check._pull_pinned_image("docker")
            self.assertEqual(run.call_count, 2)

    def test_wrong_image_id_fails_closed_without_fallback(self):
        with mock.patch.object(check, "_run", side_effect=[self.ok(), self.ok(b"sha256:wrong")]) as run:
            with self.assertRaisesRegex(RuntimeError, "unexpected image ID"):
                check._pull_pinned_image("docker")
            self.assertEqual(run.call_count, 2)

    def test_inspection_failure_fails_closed(self):
        with mock.patch.object(check, "_run", side_effect=[self.ok(), self.error(b"inspect failed")]) as run:
            with self.assertRaisesRegex(RuntimeError, "inspecting pinned Nix image"):
                check._pull_pinned_image("docker")
            self.assertEqual(run.call_count, 2)

    def test_trust_contract_only_does_not_pull(self):
        with mock.patch.object(check, "_parse_args", return_value=check.argparse.Namespace(trust_contract=check.TRUST_CONTRACT_PATH, trust_contract_only=True)), mock.patch.object(check, "_run") as run:
            self.assertEqual(check.main(), 0)
            run.assert_not_called()
