"""No host-storage effects: simulated Stage0 plan/apply admission and command ordering."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch, call

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/nixos_stage0_install.py"
SPEC = importlib.util.spec_from_file_location("heim_pc_stage0_install", SCRIPT)
assert SPEC and SPEC.loader
stage0 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage0)


def mock_disk(parts: int, model: str = "Seagate ZP4000GP304001") -> dict:
    name = "/dev/nvme0n1"
    return {"blockdevices": [{
        "name": name, "kname": name, "type": "disk", "model": model,
        "pttype": "gpt", "size": 4000787030016, "mountpoints": [None],
        "children": [
            {"name": f"{name}p{i}", "kname": f"{name}p{i}",
             "type": "part", "partuuid": f"b000000{i}-abcd-abcd-abcd-abcdefabcdef",
             "mountpoints": [None], "ro": False, "parttype": stage0.LUKS_GUID}
            for i in range(1, parts + 1)
        ],
    }]}


class Stage0SourceTests(unittest.TestCase):
    def test_no_utf8_invisible_install_contract(self):
        text = SCRIPT.read_text()
        self.assertNotIn("\u200b", text)
        self.assertIn('plan.get("no_nvram_changes")', text)
        self.assertNotIn("nixos_production_install", text.split("def main", 1)[-1])

    def test_by_id_rejects_kernel_indices(self):
        for path in ("/dev/nvme0n1", "/dev/sda", "/dev/disk/by-id/ata-WD", "nvme-foo",
                     "/dev/disk/by-id/nvme-X-part3", "/dev/disk/by-id/nvme-X/../foo"):
            with self.subTest(path=path):
                with self.assertRaises(stage0.AdmissionError):
                    stage0.by_id_disk(path)

    def test_lsblk_accepts_exact_seagate_three_and_wd_four(self):
        for expected_count, exact in ((3, True), (4, False)):
            with self.subTest(count=expected_count):
                data = mock_disk(expected_count)
                with patch.object(stage0, "output", return_value=json.dumps(data)):
                    disk, parts = stage0.disk_tree("/dev/disk/by-id/nvme-target", exact_three=exact)
                self.assertEqual(disk["name"], "/dev/nvme0n1")
                self.assertEqual(tuple(sorted(parts)), tuple(range(1, expected_count + 1)))

    def test_target_rejects_four_partitions(self):
        with patch.object(stage0, "output", return_value=json.dumps(mock_disk(4))):
            with self.assertRaisesRegex(stage0.AdmissionError, "structure"):
                stage0.disk_tree("fake")

    def test_disk_tree_rejects_forged_partition_numeration(self):
        data = mock_disk(3)
        data["blockdevices"][0]["children"][1]["name"] = "/dev/nvme1n1p2"
        with patch.object(stage0, "output", return_value=json.dumps(data)):
            with self.assertRaisesRegex(stage0.AdmissionError, "partition name"):
                stage0.disk_tree("fake")

    def test_holder_check_rejects_mounted_target_without_touching_disk(self):
        disk = mock_disk(3)["blockdevices"][0]
        disk["children"][2]["mountpoints"] = ["/media/mounted"]
        with patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "mounted"):
                stage0.no_mounts_and_holders(disk, {3: disk["children"][2]})
            mutate.assert_not_called()

    def test_hidden_signature_must_fail_closed(self):
        blob = json.dumps({"signatures": [{"type": "crypto_LUKS", "offset": "0x0"}]})
        with patch.object(stage0, "output", return_value=blob):
            with self.assertRaisesRegex(stage0.AdmissionError, "hidden"):
                stage0.hidden_signatures("mock")

    def test_missing_root_label_rejected_on_plan(self):
        with patch.object(stage0.os.path, "lexists", return_value=True):
            self.assertTrue(os.path.lexists("/dev/disk/by-label/NIXOS_STAGE0_ROOT"))

    def test_plan_creates_only_private_file_and_never_calls_mutator(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "stage0-private.json"
            source = {"revision": "a" * 40, "system": stage0.SYSTEM}
            observed = {"seagate_by_id": "target", "wd_by_id": "protected"}
            with patch.object(stage0, "check_source", return_value=source), \
                 patch.object(stage0, "live_snapshot", return_value=observed), \
                 patch.object(stage0, "host_cmd") as mutate, \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                stage0.create_plan(dest, "target", "protected")
            mutate.assert_not_called()
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            plan = json.loads(dest.read_bytes())
            self.assertEqual(plan["profile"], "nonproductive-stage0")
            self.assertEqual(plan["expected_p3_gpt_rewrite"], {
                "from": stage0.LUKS_GUID, "to": stage0.LINUX_GUID,
            })
            self.assertTrue(plan["no_nvram_changes"])
            self.assertEqual(json.loads(stdout.getvalue())["stage0"], "PLAN_ONLY")
            with patch.object(stage0, "check_source", return_value=source), \
                 patch.object(stage0, "live_snapshot", return_value=observed):
                with self.assertRaises(FileExistsError):
                    stage0.create_plan(dest, "target", "protected")

    def test_plan_owner_requirement_rejects_user_owned_file(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "test-plan.json"
            dest.write_text('{"schema_version":1,"profile":"nonproductive-stage0","no_nvram_changes":true,"wd_protected":true}')
            if os.getuid() != 0:
                with self.assertRaisesRegex(stage0.AdmissionError, "root-owned"):
                    stage0.stored_plan(dest)

    def test_stored_plan_requires_no_nvram_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "plan.json"
            dest.write_text('{"schema_version":1,"profile":"nonproductive-stage0","no_nvram_changes":false,"wd_protected":true}')
            mode = dest.stat().st_mode
            stat_result = types.SimpleNamespace(st_mode=(mode & ~0o077), st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0.Path, "lstat", return_value=stat_result):
                with self.assertRaisesRegex(stage0.AdmissionError, "unsafe"):
                    stage0.stored_plan(dest)

    def test_non_root_apply_never_calls_host_mutator(self):
        with patch.object(stage0.os, "geteuid", return_value=1000), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "must be root"):
                stage0.apply_plan(Path("/root/private"), "no")
            mutate.assert_not_called()

    def test_noninteractive_apply_never_calls_host_mutator(self):
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=False), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "TTY"):
                stage0.apply_plan(Path("/root/private"), "no")
            mutate.assert_not_called()

    def test_wrong_confirmation_never_calls_host_mutator(self):
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=True), \
             patch.object(stage0.sys.stderr, "isatty", return_value=True), \
             patch.object(stage0, "stored_plan", return_value=({"schema_version": 1}, "a"*64)), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "confirmation"):
                stage0.apply_plan(Path("/root/private"), "wrong")
            mutate.assert_not_called()

    def test_source_mismatch_stops_before_partition_ops(self):
        saved = {"source": {"revision": "a"*40}, "snapshot": {"seagate_by_id": "target", "wd_by_id": "protected"}}
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=True), \
             patch.object(stage0.sys.stderr, "isatty", return_value=True), \
             patch.object(stage0, "stored_plan", return_value=(saved, "f"*64)), \
             patch.object(stage0, "check_source", return_value={"revision": "b"*40}), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "source"):
                stage0.apply_plan(Path("/root/private"), "APPLY-STAGE0:"+"f"*64)
            mutate.assert_not_called()

    def test_snapshot_drift_stops_before_partition_ops(self):
        saved = {"source": {"revision": "a"*40}, "snapshot": {"seagate_by_id": "target", "wd_by_id": "protected", "state": "before"}}
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=True), \
             patch.object(stage0.sys.stderr, "isatty", return_value=True), \
             patch.object(stage0, "stored_plan", return_value=(saved, "f"*64)), \
             patch.object(stage0, "check_source", return_value=saved["source"]), \
             patch.object(stage0, "live_snapshot", return_value={**saved["snapshot"], "state": "after"}), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "hardware"):
                stage0.apply_plan(Path("/root/private"), "APPLY-STAGE0:"+"f"*64)
            mutate.assert_not_called()

    def test_run_container_is_target_scoped_no_network_readonly_nix(self):
        source = {"volume": stage0.BUILD_VOLUME, "image": stage0.NIX_IMAGE,
                  "installer": "/nix/store/"+"a"*32+"-nixos-install", "system": stage0.SYSTEM}
        with patch.object(stage0, "host_cmd") as mutate:
            stage0.run_container(source)
        command = mutate.call_args.args
        self.assertEqual(command[0], "/usr/bin/docker")
        self.assertIn("--network=none", command)
        self.assertIn("--security-opt=apparmor=unconfined", command)
        self.assertIn("readonly", " ".join(command))
        self.assertIn(str(stage0.NIX_ROOT), " ".join(command))
        self.assertIn("--no-root-passwd", command)
        self.assertNotIn("/dev/nvme0n1", " ".join(command))
        self.assertNotIn("efibootmgr", " ".join(command))

    def test_host_toolchain_admission_rejects_missing_mkfs_before_mutation(self):
        def fake_which(name, *, path=None):
            if name == "mkfs.btrfs":
                return None
            return "/usr/bin/" + name
        with patch.object(stage0.shutil, "which", side_effect=fake_which), \
             patch.object(stage0.Path, "is_file", return_value=True), \
             patch.object(stage0.os, "access", return_value=True), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "mkfs.btrfs"):
                stage0.verify_host_tools()
        mutate.assert_not_called()

    def test_host_toolchain_requires_real_btrfs_version(self):
        with patch.object(stage0.shutil, "which", side_effect=lambda n, path=None: "/usr/bin/" + n), \
             patch.object(stage0.Path, "is_file", return_value=True), \
             patch.object(stage0.os, "access", return_value=True), \
             patch.object(stage0, "output", side_effect=["", "btrfs-progs v5.16.2"]), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "unusable host Btrfs tool"):
                stage0.verify_host_tools()
        mutate.assert_not_called()

    def test_mount_namespace_preflight_has_no_disks_and_no_network(self):
        source = {"volume": stage0.BUILD_VOLUME, "image": stage0.NIX_IMAGE}
        with patch.object(stage0, "host_cmd") as executor:
            stage0.verify_install_namespace(source)
        cmd = executor.call_args.args
        self.assertEqual(cmd[:3], ("/usr/bin/docker", "run", "--rm"))
        self.assertIn("--network=none", cmd)
        self.assertIn("--security-opt=apparmor=unconfined", cmd)
        self.assertIn("--security-opt=seccomp=unconfined", cmd)
        self.assertIn("--cap-add=SYS_ADMIN", cmd)
        self.assertIn("readonly", " ".join(cmd))
        self.assertNotIn("/dev/", " ".join(cmd))
        self.assertNotIn("type=bind", " ".join(cmd))
        self.assertNotIn("--privileged", cmd)

    def test_offline_store_copy_is_target_scoped_and_uses_local_unsigned_paths(self):
        source = {"volume": stage0.BUILD_VOLUME, "image": stage0.NIX_IMAGE,
                  "system": stage0.SYSTEM}
        with patch.object(stage0, "host_cmd") as mutate:
            stage0.copy_source_closure_to_target(source)
        argv = mutate.call_args.args
        self.assertEqual(argv[:3], ("/usr/bin/docker", "run", "--rm"))
        self.assertIn("--network=none", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--cap-add=CHOWN", argv)
        self.assertIn("--no-check-sigs", argv)
        self.assertIn("local?root=/mnt", argv)
        self.assertIn(stage0.SYSTEM, argv)
        self.assertIn("type=bind,src="+str(stage0.NIX_ROOT)+",dst=/mnt", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--cap-add=SYS_ADMIN", argv)
        self.assertNotIn("/dev/nvme0n1", " ".join(argv))
        self.assertNotIn("readonly", " ".join(argv))

    def test_reverify_source_closure_has_no_block_device_mounts(self):
        source = {"volume": stage0.BUILD_VOLUME, "image": stage0.NIX_IMAGE,
                  "system": stage0.SYSTEM}
        with patch.object(stage0, "host_cmd") as verify:
            stage0.verify_source_store(source)
        argv = verify.call_args.args
        self.assertIn("--network=none", argv)
        self.assertIn("verify", argv)
        self.assertIn("--recursive", argv)
        self.assertIn(stage0.SYSTEM, argv)
        self.assertNotIn("--cap-add=SYS_ADMIN", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("/dev/", " ".join(argv))

    def test_credential_hash_uses_stdin_no_password_argument(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0,
                                               stdout=b"$6$salt$somehash\n", stderr=b"")
        with patch.object(stage0, "run", return_value=completed) as wrapper:
            hashed = stage0.output_hash("private-secret-sent-to-stdin", "salt")
        self.assertEqual(hashed, "$6$salt$somehash")
        self.assertNotIn("private-secret-sent-to-stdin", " ".join(map(str, wrapper.call_args.args)))
        self.assertIn(b"private-secret-sent-to-stdin", wrapper.call_args.kwargs["input_bytes"])

    def test_weak_password_rejected_before_shadow_change(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("root:!:1:0:99999:7:::\nalex:!:1:0:99999:7:::\n")
            original = shadow.read_bytes()
            shadow_meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0, "validated_shadow_metadata", return_value=shadow_meta), \
                 patch.object(stage0.getpass, "getpass", side_effect=["short", "short"]), \
                 patch.object(stage0, "output_hash") as hasher:
                with self.assertRaisesRegex(stage0.AdmissionError, "at least 16"):
                    stage0.credential_bootstrap(shadow)
            self.assertEqual(shadow.read_bytes(), original)
            hasher.assert_not_called()

    def test_secure_hash_saved_to_shadow_without_plaintxt(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("root:!:1:0:99999:7:::\nalex:!:1:0:99999:7:::\n")
            shadow_meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0, "validated_shadow_metadata", return_value=shadow_meta), \
                 patch.object(stage0.getpass, "getpass",
                              side_effect=["unique-password-with-23-symbols", "unique-password-with-23-symbols"]), \
                 patch.object(stage0, "output_hash", return_value="$6$salt$hashdata"), \
                 patch.object(stage0.os, "fchown") as preserve_owner:
                stage0.credential_bootstrap(shadow)
                preserve_owner.assert_called_once()
            value = shadow.read_text()
            self.assertIn("alex:$6$salt$hashdata:", value)
            self.assertNotIn("unique-password", value)
            self.assertEqual(stat.S_IMODE(shadow.stat().st_mode), 0o600)

    def test_simulated_apply_obeys_exact_target_partition_order(self):
        # All storage/external calls are mocked; NO block device, mount or EFI is touched.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "stage0-root"
            source = {"revision": "a"*40, "system": stage0.SYSTEM,
                      "installer": "/nix/store/"+"a"*32+"-nixos-install",
                      "image": stage0.NIX_IMAGE, "volume": stage0.BUILD_VOLUME,
                      "script_sha256": "f"*64}
            target = "/dev/disk/by-id/nvme-seagate"
            wd = "/dev/disk/by-id/nvme-protected-wd"
            snapshot = {
                "seagate_by_id": target, "wd_by_id": wd,
                "seagate_parts": {
                    j: {"partuuid": f"1234567{j}-abcd-abcd-abcd-0123456789ab",
                        "size": 3_995_417_255_424 if j == 3 else 1_073_741_824,
                        "name": f"/dev/nvme0n1p{j}"} for j in range(1, 4)
                },
            }
            plan = {"source": source, "snapshot": snapshot}
            patched_p3 = dict(snapshot["seagate_parts"][3],
                              parttype=stage0.LINUX_GUID, partlabel=stage0.ROOT_LABEL)
            modified = dict(snapshot["seagate_parts"])
            modified[3] = patched_p3
            commands = []
            def host(*argv):
                commands.append(argv)
                if argv[:3] == ("btrfs", "subvolume", "create"):
                    Path(argv[-1]).mkdir()
            def output(*argv):
                if argv[:3] == ("docker", "image", "inspect"):
                    return source["image"]
                if argv[:3] == ("docker", "volume", "inspect"):
                    return json.dumps([{"Driver": "local"}])
                raise AssertionError(f"unexpected synthetic output {argv}")

            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(stage0, "NIX_ROOT", path))
                stack.enter_context(patch.object(stage0.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(stage0.sys.stdin, "isatty", return_value=True))
                stack.enter_context(patch.object(stage0.sys.stderr, "isatty", return_value=True))
                stack.enter_context(patch.object(stage0.Path, "is_mount", return_value=False))
                stack.enter_context(patch.object(stage0, "stored_plan", return_value=(plan, "d"*64)))
                stack.enter_context(patch.object(stage0, "check_source", return_value=source))
                stack.enter_context(patch.object(stage0, "live_snapshot", return_value=snapshot))
                stack.enter_context(patch.object(stage0, "disk_tree", return_value=({"name": "/dev/nvme0n1"}, modified)))
                stack.enter_context(patch.object(stage0, "output", side_effect=output))
                stack.enter_context(patch.object(stage0.os.path, "realpath", return_value=patched_p3["name"]))
                stack.enter_context(patch.object(stage0, "hidden_signatures"))
                fingerprints = stack.enter_context(patch.object(stage0, "same_protected_fingerprint"))
                verify_tools = stack.enter_context(patch.object(stage0, "verify_host_tools"))
                verify_namespace = stack.enter_context(patch.object(stage0, "verify_install_namespace"))
                verify_store = stack.enter_context(patch.object(stage0, "verify_source_store"))
                copy_store = stack.enter_context(patch.object(stage0, "copy_source_closure_to_target"))
                installer = stack.enter_context(patch.object(stage0, "run_container"))
                esp = stack.enter_context(patch.object(stage0, "verify_installed_esp"))
                credentials = stack.enter_context(patch.object(stage0, "credential_bootstrap"))
                stack.enter_context(patch.object(stage0, "host_cmd", side_effect=host))
                with contextlib.redirect_stdout(io.StringIO()) as capture:
                    stage0.apply_plan(Path("/simulated/plan"), "APPLY-STAGE0:"+"d"*64)
            self.assertEqual(json.loads(capture.getvalue())["stage0"],
                             "INSTALLED_REQUIRES_PHYSICAL_BOOT_TEST")
            formatted = [cmd for cmd in commands if cmd[0] == "mkfs.btrfs"]
            self.assertEqual(formatted, [("mkfs.btrfs", "-L", stage0.ROOT_LABEL,
                                         target+"-part3")])
            gpt = [cmd for cmd in commands if cmd[0] == "sgdisk"]
            self.assertEqual(len(gpt), 1)
            self.assertEqual(gpt[0][-1], target)
            self.assertLess(commands.index(gpt[0]), commands.index(formatted[0]))
            self.assertEqual(
                [cmd[-1] for cmd in commands if cmd[:3] == ("btrfs", "subvolume", "create")],
                [str(path / subvol) for subvol in stage0.SUBVOLS])
            self.assertFalse(any(wd in " ".join(cmd) for cmd in commands))
            self.assertEqual(len([c for c in commands if c[0] == "mount"]), 7)
            self.assertEqual(len([c for c in commands if c[0] == "umount"]), 7)
            self.assertEqual(fingerprints.call_count, 3)
            verify_tools.assert_called_once_with()
            verify_namespace.assert_called_once_with(source)
            verify_store.assert_called_once_with(source)
            copy_store.assert_called_once_with(source)
            installer.assert_called_once_with(source)
            esp.assert_called_once()
            credentials.assert_called_once_with(path / "etc/shadow")

    def test_password_bootstrap_never_overwrites_preexisting_hash(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("root:!:1:0:99999:7:::\nalex:$6$old$existing:1:0:99999:7:::\n")
            before = shadow.read_bytes()
            shadow_meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0, "validated_shadow_metadata", return_value=shadow_meta), \
                 patch.object(stage0.getpass, "getpass", side_effect=["secret-of-length-at-least-16"]*2), \
                 patch.object(stage0, "output_hash", return_value="$6$new$hash"):
                with self.assertRaisesRegex(stage0.AdmissionError, "already has a password"):
                    stage0.credential_bootstrap(shadow)
            self.assertEqual(shadow.read_bytes(), before)

    def test_uefi_loader_entry_matches_evaluated_root_fstab(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            boot = root / "boot"
            efi = boot / "EFI/BOOT/BOOTX64.EFI"
            entry = boot / "loader/entries/nixos-generation-1.conf"
            efi.parent.mkdir(parents=True)
            entry.parent.mkdir(parents=True)
            efi.write_bytes(b"simulated systemd-boot EFI file")
            (root / "etc").mkdir()
            (root / "etc/shadow").write_text("alex:!:1:0:99999:7:::\n")
            entry.write_text(
                "title NixOS Stage0\n"
                "linux /EFI/nixos/stage0-linux.efi\n"
                "initrd /EFI/nixos/stage0-initrd.efi\n"
                "options init=/nix/store/exact-system/init nomodeset root=fstab loglevel=4\n"
            )
            with patch.object(stage0, "NIX_ROOT", root):
                stage0.verify_installed_esp()
                entry.write_text(entry.read_text().replace("root=fstab", "root=/dev/sda1"))
                with self.assertRaisesRegex(stage0.AdmissionError, "root=fstab"):
                    stage0.verify_installed_esp()

    def test_shadow_metadata_rejects_world_readable_or_nonroot(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("alex:!:1:0:99999:7:::\n")
            with self.assertRaisesRegex(stage0.AdmissionError, "ownership or permissions"):
                stage0.validated_shadow_metadata(shadow)

    def test_protected_esp_digest_changes_on_bit_flip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            file = root / "EFI" / "BOOTX64.EFI"
            file.parent.mkdir()
            file.write_bytes(b"start")
            a = stage0.wd_esp_tree_fingerprint(root)
            file.write_bytes(b"start!")
            b = stage0.wd_esp_tree_fingerprint(root)
            self.assertNotEqual(a, b)
            self.assertEqual(a, stage0.digest(b"EFI/BOOTX64.EFI\0" + b"5\0" + b"start\0"))

    def test_protected_esp_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "file").write_bytes(b"valid")
            (root / "link").symlink_to("file")
            with self.assertRaisesRegex(stage0.AdmissionError, "unexpected"):
                stage0.wd_esp_tree_fingerprint(root)


if __name__ == "__main__":
    unittest.main()