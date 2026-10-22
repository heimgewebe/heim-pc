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


def sealed_source() -> dict:
    return {"revision": "a"*40, "build_revision": stage0.BUILD_REV,
            "source_kind": "sealed-oci-stage0-v1",
            "system": stage0.SYSTEM, "installer": stage0.INSTALLER,
            "image": stage0.SEALED_IMAGE, "builder_image": stage0.NIX_IMAGE,
            "script_sha256": "b"*64}


def sealed_nar_info() -> str:
    return json.dumps({
        path: {"narHash": nar_hash, "narSize": nar_size}
        for path, (nar_hash, nar_size) in stage0.SEALED_NAR.items()
    })


class Stage0SourceTests(unittest.TestCase):
    def test_frozen_stage0_profile_btrfs_and_no_default_passwords(self):
        source = (stage0.ROOT / "nixos/system/modules/stage0-no-usb.nix").read_text()
        self.assertIn('rootDevice = "/dev/disk/by-label/NIXOS_STAGE0_ROOT";', source)
        for mount, subvol in (("/", "@root"), ("/nix", "@nix"),
                              ("/home", "@home"), ("/persist", "@persist")):
            self.assertIn(f'fileSystems."{mount}" = subvolume "{subvol}";', source)
        self.assertIn('fsType = "btrfs";', source)
        self.assertIn('device = rootDevice;', source)
        self.assertIn('options = [ "subvol=${name}" "compress=zstd" ];', source)
        self.assertIn('device = "/dev/disk/by-label/NIXOS2_EFI";', source)
        self.assertIn('security.sudo.wheelNeedsPassword = true;', source)
        self.assertIn('users.mutableUsers = true;', source)
        for secret in ('hashedPassword =', 'initialPassword =', 'initialHashedPassword =',
                       'hashedPasswordFile ='):
            self.assertNotIn(secret, source)
        self.assertIn('boot.loader.efi.canTouchEfiVariables = false;', source)

    def test_pinned_installer_cannot_be_replaced_by_sidecar(self):
        fake = {
            str(stage0.BUILD_STATE / "source-head"): stage0.BUILD_REV,
            str(stage0.BUILD_STATE / "closure-path"): stage0.SYSTEM,
            str(stage0.BUILD_STATE / "nix-image"): stage0.NIX_IMAGE,
            str(stage0.BUILD_STATE / "stage0-tools"): stage0.INSTALLER,
        }
        def fake_output(*argv):
            if argv[-2:] == ("rev-parse", "HEAD"):
                return "f" * 40
            return ""
        with patch.object(stage0, "output", side_effect=fake_output), \
             patch.object(stage0, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")), \
             patch.object(stage0, "read_text", side_effect=lambda p: fake[str(p)]):
            self.assertEqual(stage0.check_source()["installer"], stage0.INSTALLER)
            fake[str(stage0.BUILD_STATE / "stage0-tools")] = "/nix/store/" + "a"*32 + "-nixos-install"
            with self.assertRaisesRegex(stage0.AdmissionError, "differs"):
                stage0.check_source()

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
        # Never read the developer/CI runner's actual sysfs holders.
        with patch.object(stage0.Path, "is_dir", return_value=True), \
             patch.object(stage0.Path, "iterdir", return_value=iter(())), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "mounted"):
                stage0.no_mounts_and_holders(disk, {3: disk["children"][2]})
            mutate.assert_not_called()

    def test_kernel_holder_refuses_even_if_unmounted(self):
        disk = mock_disk(3)["blockdevices"][0]
        with patch.object(stage0.Path, "is_dir", return_value=True), \
             patch.object(stage0.Path, "iterdir", return_value=iter([Path("mapper")])), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "holder"):
                stage0.no_mounts_and_holders(disk, {3: disk["children"][2]})
            mutate.assert_not_called()

    def test_hidden_signature_must_fail_closed(self):
        blob = json.dumps({"signatures": [{"type": "crypto_LUKS", "offset": "0x0"}]})
        with patch.object(stage0, "output", return_value=blob):
            with self.assertRaisesRegex(stage0.AdmissionError, "hidden"):
                stage0.hidden_signatures("mock")

    def test_missing_root_label_rejected_on_plan(self):
        disk = {"name": "/dev/nvme0n1", "model": "Seagate ZP4000GP304001",
                "size": 4_000_000_000_000, "pttype": "gpt"}
        wd = {"name": "/dev/nvme1n1", "model": "WD_BLACK SN850X",
              "size": 2_000_000_000_000, "pttype": "gpt"}
        parts = {n: {"name": f"/dev/nvme0n1p{n}",
                     "partuuid": f"0000000{n}-0000-0000-0000-000000000001"}
                 for n in (1, 2, 3)}
        parts[1].update(parttype=stage0.EFI_GUID, fstype="vfat", label=stage0.EFI_LABEL)
        parts[2].update(fstype="ext4", label=stage0.RECOVERY_LABEL)
        parts[3].update(parttype=stage0.LUKS_GUID, partlabel="NIXOS2_CRYPT",
                        fstype=None, uuid=None, size=stage0.MIN_ROOT_SIZE)
        with patch.object(stage0, "by_id_disk", side_effect=["/dev/nvme0n1", "/dev/nvme1n1"]), \
             patch.object(stage0.os, "stat", side_effect=[
                 types.SimpleNamespace(st_rdev=10), types.SimpleNamespace(st_rdev=11)]), \
             patch.object(stage0, "disk_tree", side_effect=[(disk, parts), (wd, {})]), \
             patch.object(stage0, "no_mounts_and_holders"), \
             patch.object(stage0, "protected_mounts_on_wd"), \
             patch.object(stage0, "part_path"), \
             patch.object(stage0, "hidden_signatures"), \
             patch.object(stage0.os.path, "lexists", return_value=True), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "occupied Stage0 root label"):
                stage0.live_snapshot("/dev/disk/by-id/nvme-seagate", "/dev/disk/by-id/nvme-wd")
            mutate.assert_not_called()
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
            dest.write_text("{}")
            os.chmod(dest, 0o600)
            original = dest.stat()
            stat_result = types.SimpleNamespace(st_mode=original.st_mode, st_uid=1000, st_nlink=1)
            with patch.object(stage0.os, "fstat", return_value=stat_result):
                with self.assertRaisesRegex(stage0.AdmissionError, "root-owned"):
                    stage0.stored_plan(dest)
    def test_stored_plan_requires_no_nvram_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "plan.json"
            dest.write_text(json.dumps({
                "schema_version": 1, "profile": "nonproductive-stage0",
                "no_nvram_changes": False, "wd_protected": True,
                "required_root_label": stage0.ROOT_LABEL,
                "expected_p3_gpt_rewrite": {"from": stage0.LUKS_GUID, "to": stage0.LINUX_GUID},
            }))
            os.chmod(dest, 0o600)
            st = dest.stat()
            with patch.object(stage0.os, "fstat", return_value=types.SimpleNamespace(
                st_mode=st.st_mode, st_uid=0, st_nlink=1)):
                with self.assertRaisesRegex(stage0.AdmissionError, "unsafe"):
                    stage0.stored_plan(dest)
    def test_cleanup_error_fails_closed_and_reports_alarm(self):
        mounts = [Path("/mock-root"), Path("/mock-root/boot")]
        def fake_umount(*args):
            if args[-1].endswith("/boot"):
                raise stage0.AdmissionError("simulated busy mount")
        with patch.object(stage0, "host_cmd", side_effect=fake_umount) as cmd, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaisesRegex(stage0.AdmissionError, "cleanup incomplete"):
                stage0.cleanup_target_mounts(mounts)
        self.assertIn("ALARM", stderr.getvalue())
        self.assertEqual([c.args for c in cmd.call_args_list],
                         [("umount", "/mock-root/boot"), ("umount", "/mock-root")])

    def test_cleanup_zero_exit_but_mount_remains_fails_closed(self):
        with patch.object(stage0, "host_cmd") as unmount, \
             patch.object(stage0.Path, "is_mount", return_value=True), \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaisesRegex(stage0.AdmissionError, "cleanup incomplete"):
                stage0.cleanup_target_mounts([Path("/mock-root")])
        self.assertIn("ALARM", stderr.getvalue())
        unmount.assert_called_once_with("umount", "/mock-root")

    def test_cleanup_success_reverse_order(self):
        with patch.object(stage0, "host_cmd") as cmd, \
             patch.object(stage0.Path, "is_mount", return_value=False):
            stage0.cleanup_target_mounts([Path("/mock-root"), Path("/mock-root/boot")])
        self.assertEqual([c.args for c in cmd.call_args_list],
                         [("umount", "/mock-root/boot"), ("umount", "/mock-root")])

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

    def test_immutable_source_missing_seal_blocks_before_any_device_command(self):
        source = sealed_source()
        source["revision"] = "b"*40
        plan = {"source": source, "snapshot":
                {"seagate_by_id": "/dev/disk/by-id/nvme-seagate",
                 "wd_by_id": "/dev/disk/by-id/nvme-wd"}}
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=True), \
             patch.object(stage0.sys.stderr, "isatty", return_value=True), \
             patch.object(stage0, "stored_plan", return_value=(plan, "f"*64)), \
             patch.object(stage0, "check_source", return_value=source), \
             patch.object(stage0, "live_snapshot") as snapshot, \
             patch.object(stage0, "verify_source_store") as verify, \
             patch.object(stage0, "copy_source_closure_to_target") as copy, \
             patch.object(stage0, "run_container") as install, \
             patch.object(stage0, "SEALED_SOURCE_ATTESTATION", Path("/impossible-stage0-seal/absent")) as unused_seal, \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "physical Apply BLOCKED"):
                stage0.apply_plan(Path("/nonexistent/test-plan"), "APPLY-STAGE0:"+"f"*64)
            snapshot.assert_not_called()
            verify.assert_not_called()
            copy.assert_not_called()
            install.assert_not_called()
            mutate.assert_not_called()

    def test_immutable_source_guard_rejects_other_docker_volume(self):
        with self.assertRaisesRegex(stage0.AdmissionError, "unsealed or mutable"):
            stage0.require_immutable_install_source({"volume": "untrusted-docker-volume"})

    def test_snapshot_drift_stops_before_partition_ops(self):
        saved = {"source": {"revision": "a"*40}, "snapshot": {"seagate_by_id": "target", "wd_by_id": "protected", "state": "before"}}
        with patch.object(stage0.os, "geteuid", return_value=0), \
             patch.object(stage0.sys.stdin, "isatty", return_value=True), \
             patch.object(stage0.sys.stderr, "isatty", return_value=True), \
             patch.object(stage0, "stored_plan", return_value=(saved, "f"*64)), \
             patch.object(stage0, "check_source", return_value=saved["source"]), \
             patch.object(stage0, "require_immutable_install_source"), \
             patch.object(stage0, "live_snapshot", return_value={**saved["snapshot"], "state": "after"}), \
             patch.object(stage0, "host_cmd") as mutate:
            with self.assertRaisesRegex(stage0.AdmissionError, "hardware"):
                stage0.apply_plan(Path("/root/private"), "APPLY-STAGE0:"+"f"*64)
            mutate.assert_not_called()

    def test_run_container_is_target_scoped_no_network_readonly_nix(self):
        source = {"source_kind": "sealed-oci-stage0-v1", "image": stage0.SEALED_IMAGE,
                  "installer": "/nix/store/"+"a"*32+"-nixos-install", "system": stage0.SYSTEM}
        with patch.object(stage0, "host_cmd") as mutate:
            stage0.run_container(source)
        command = mutate.call_args.args
        self.assertEqual(command[0], "/usr/bin/docker")
        self.assertIn("--network=none", command)
        self.assertIn("--security-opt=apparmor=unconfined", command)
        self.assertIn("--pull=never", command)
        self.assertIn(stage0.SEALED_IMAGE, command)
        self.assertIn("/busybox", command)
        self.assertNotIn("type=volume", " ".join(command))
        self.assertNotIn(stage0.BUILD_VOLUME, " ".join(command))
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
        source = sealed_source()
        with patch.object(stage0, "host_cmd") as executor:
            stage0.verify_install_namespace(source)
        cmd = executor.call_args.args
        self.assertEqual(cmd[:3], ("/usr/bin/docker", "run", "--rm"))
        self.assertIn("--network=none", cmd)
        self.assertIn("--security-opt=apparmor=unconfined", cmd)
        self.assertIn("--security-opt=seccomp=unconfined", cmd)
        self.assertIn(stage0.UTIL_LINUX + "/bin/unshare", cmd)
        self.assertIn(stage0.UTIL_LINUX + "/bin/mount", cmd)
        self.assertNotIn("/nix/var/nix/profiles/default/bin/bash", cmd)
        self.assertIn("--cap-add=SYS_ADMIN", cmd)
        self.assertIn(stage0.SEALED_IMAGE, cmd)
        self.assertNotIn("type=volume", " ".join(cmd))
        self.assertNotIn("/dev/", " ".join(cmd))
        self.assertNotIn("type=bind", " ".join(cmd))
        self.assertNotIn("--privileged", cmd)

    def test_offline_store_copy_is_target_scoped_and_uses_local_unsigned_paths(self):
        source = {"source_kind": "sealed-oci-stage0-v1", "image": stage0.SEALED_IMAGE,
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
        self.assertIn("--cap-add=SYS_ADMIN", argv)
        self.assertNotIn("type=volume", " ".join(argv))
        self.assertNotIn(stage0.BUILD_VOLUME, " ".join(argv))
        self.assertNotIn("/dev/nvme0n1", " ".join(argv))
        self.assertIn(stage0.SEALED_IMAGE, argv)
        self.assertIn("--pull=never", argv)

    def test_verifier_checks_system_and_pinned_installer(self):
        source = {"source_kind": "sealed-oci-stage0-v1", "image": stage0.SEALED_IMAGE,
                  "system": stage0.SYSTEM, "installer": stage0.INSTALLER}
        with patch.object(stage0, "host_cmd") as verify, \
             patch.object(stage0, "output", return_value=sealed_nar_info()) as nar:
            stage0.verify_source_store(source)
        nar.assert_called_once()
        argv = verify.call_args.args
        self.assertIn("--recursive", argv)
        self.assertIn(stage0.SYSTEM, argv)
        self.assertIn(stage0.INSTALLER, argv)
        self.assertIn(stage0.UTIL_LINUX, argv)

    def test_reverify_source_closure_has_no_block_device_mounts(self):
        source = {"source_kind": "sealed-oci-stage0-v1", "image": stage0.SEALED_IMAGE,
                  "system": stage0.SYSTEM, "installer": stage0.INSTALLER}
        with patch.object(stage0, "host_cmd") as verify:
            stage0.verify_source_store(source)
        argv = verify.call_args.args
        self.assertIn("--network=none", argv)
        self.assertIn("verify", argv)
        self.assertIn("--recursive", argv)
        self.assertIn(stage0.SYSTEM, argv)
        self.assertIn("--cap-add=SYS_ADMIN", argv)
        self.assertNotIn("type=volume", " ".join(argv))
        self.assertNotIn(stage0.BUILD_VOLUME, " ".join(argv))
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
        with patch.object(stage0.getpass, "getpass", side_effect=["short", "short"]*3) as prompt, \
             patch.object(stage0, "output_hash") as hasher, \
             patch.object(stage0, "host_cmd") as disk, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(stage0.AdmissionError, "at least 16"):
                stage0.prepare_private_credential_hash()
            self.assertEqual(prompt.call_count, 6)
            hasher.assert_not_called()
            disk.assert_not_called()
    def test_password_retry_succeeds_only_after_matching_long_secret(self):
        secret = "private-stage0-password-length-32"
        with patch.object(stage0.getpass, "getpass", side_effect=[
                 "mistake", "mistake", secret, secret]) as prompt, \
             patch.object(stage0, "output_hash", return_value="$6$saltsalt$hashdata") as hasher, \
             patch.object(stage0, "host_cmd") as disk, \
             contextlib.redirect_stderr(io.StringIO()):
            result = stage0.prepare_private_credential_hash()
        self.assertEqual(result, "$6$saltsalt$hashdata")
        self.assertEqual(prompt.call_count, 4)
        hasher.assert_called_once()
        self.assertEqual(hasher.call_args.args[0], secret)
        disk.assert_not_called()

    def test_source_git_uses_exact_checkout_scoped_safety(self):
        args = stage0.git_args("status", "--porcelain")
        self.assertEqual(args[0], "git")
        self.assertIn(f"safe.directory={stage0.ROOT}", args)
        self.assertIn("core.fsmonitor=false", args)
        self.assertIn("core.hooksPath=/dev/null", args)
        self.assertEqual(args[-2:], ("status", "--porcelain"))

    def test_stored_plan_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"
            alias = Path(td) / "alias"
            target.write_text("{}")
            alias.symlink_to(target.name)
            with self.assertRaises(OSError):
                stage0.stored_plan(alias)

    def test_plan_validation_rejects_wrong_root_label_on_same_open_inode(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan"
            path.write_text(json.dumps({
                "schema_version": 1, "profile": "nonproductive-stage0",
                "no_nvram_changes": True, "wd_protected": True,
                "required_root_label": "ATTACKER_LABEL",
                "expected_p3_gpt_rewrite": {"from": stage0.LUKS_GUID, "to": stage0.LINUX_GUID},
            }))
            os.chmod(path, 0o600)
            st = path.stat()
            with patch.object(stage0.os, "fstat", return_value=types.SimpleNamespace(
                st_mode=st.st_mode, st_uid=0, st_nlink=1)):
                with self.assertRaisesRegex(stage0.AdmissionError, "unsafe"):
                    stage0.stored_plan(path)

    def test_stored_plan_normalizes_json_partition_numbers_on_one_inode(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan.json"
            path.write_text(json.dumps({
                "schema_version": 1, "profile": "nonproductive-stage0",
                "no_nvram_changes": True, "wd_protected": True,
                "required_root_label": stage0.ROOT_LABEL,
                "expected_p3_gpt_rewrite": {
                    "from": stage0.LUKS_GUID, "to": stage0.LINUX_GUID,
                },
                "snapshot": {
                    "seagate_parts": {"1": {"size": 1024}, "3": {"size": 4096}},
                    "wd_parts": {"2": {"size": 8192}},
                },
            }))
            os.chmod(path, 0o600)
            original = path.read_bytes()
            st = path.stat()
            with patch.object(stage0.os, "fstat", return_value=types.SimpleNamespace(
                st_uid=0, st_mode=st.st_mode, st_nlink=1)), \
                 patch.object(stage0.Path, "read_bytes", side_effect=AssertionError("TOCTOU")):
                plan, digest = stage0.stored_plan(path)
            self.assertEqual(digest, stage0.digest(original))
            self.assertEqual(sorted(plan["snapshot"]["seagate_parts"]), [1, 3])
            self.assertEqual(sorted(plan["snapshot"]["wd_parts"]), [2])

    def test_stored_plan_rejects_forged_gpt_partition_key(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan.json"
            path.write_text(json.dumps({
                "schema_version": 1, "profile": "nonproductive-stage0",
                "no_nvram_changes": True, "wd_protected": True,
                "required_root_label": stage0.ROOT_LABEL,
                "expected_p3_gpt_rewrite": {
                    "from": stage0.LUKS_GUID, "to": stage0.LINUX_GUID,
                },
                "snapshot": {"seagate_parts": {"3;bad": {}}},
            }))
            os.chmod(path, 0o600)
            st = path.stat()
            with patch.object(stage0.os, "fstat", return_value=types.SimpleNamespace(
                st_uid=0, st_mode=st.st_mode, st_nlink=1)):
                with self.assertRaisesRegex(stage0.AdmissionError, "indices"):
                    stage0.stored_plan(path)

    def test_hashing_malformed_output_fails_before_first_storage_operation(self):
        value = "compliant-stage0-password-123456789"
        with patch.object(stage0.getpass, "getpass", side_effect=[value, value]), \
             patch.object(stage0, "output_hash", return_value="$6$malformed"), \
             patch.object(stage0, "host_cmd") as disk:
            with self.assertRaisesRegex(stage0.AdmissionError, "invalid private password hash"):
                stage0.prepare_private_credential_hash()
            disk.assert_not_called()

    def test_nonsecret_stderr_is_bounded_but_hash_input_never_logged(self):
        failed = subprocess.CompletedProcess([], 3, b"", b"reason: read-only FAT volume\nsecond detail")
        with patch.object(stage0.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(stage0.AdmissionError, "read-only FAT volume"):
                stage0.run("mkfs.btrfs", "--version")
            with self.assertRaises(stage0.AdmissionError) as secret:
                stage0.run("/usr/bin/openssl", "passwd", "-stdin",
                           input_bytes=b"password-value-should-not-leak\n")
        self.assertNotIn("password-value", str(secret.exception))
        self.assertNotIn("reason:", str(secret.exception))

    def test_secure_hash_saved_to_shadow_without_plaintxt(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("root:!:1:0:99999:7:::\nalex:!:1:0:99999:7:::\n")
            shadow_meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0, "validated_shadow_metadata", return_value=shadow_meta), \
                 patch.object(stage0.getpass, "getpass") as prompt, \
                 patch.object(stage0.os, "fchown") as preserve_owner:
                stage0.credential_bootstrap(shadow, "$6$salt$hashdata")
                preserve_owner.assert_called_once()
                prompt.assert_not_called()
            value = shadow.read_text()
            self.assertIn("alex:$6$salt$hashdata:", value)
            self.assertEqual(stat.S_IMODE(shadow.stat().st_mode), 0o600)

    def test_simulated_apply_obeys_exact_target_partition_order(self):
        # All storage/external calls are mocked; NO block device, mount or EFI is touched.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "stage0-root"
            path.mkdir()  # Existing empty host mountpoint, never a real block mount.
            source = sealed_source()
            source["script_sha256"] = "f"*64
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
                stack.enter_context(patch.object(stage0, "require_immutable_install_source"))
                stack.enter_context(patch.object(stage0, "live_snapshot", return_value=snapshot))
                stack.enter_context(patch.object(stage0, "disk_tree", return_value=({"name": "/dev/nvme0n1"}, modified)))
                stack.enter_context(patch.object(stage0, "output", side_effect=output))
                stack.enter_context(patch.object(stage0.os.path, "realpath", return_value=patched_p3["name"]))
                stack.enter_context(patch.object(stage0, "hidden_signatures"))
                fingerprints = stack.enter_context(patch.object(stage0, "same_protected_fingerprint"))
                verify_tools = stack.enter_context(patch.object(stage0, "verify_host_tools"))
                verify_namespace = stack.enter_context(patch.object(stage0, "verify_install_namespace"))
                password_hash = stack.enter_context(patch.object(stage0, "prepare_private_credential_hash",
                                                                  return_value="$6$test$hash"))
                verify_store = stack.enter_context(patch.object(stage0, "verify_source_store"))
                copy_store = stack.enter_context(patch.object(stage0, "copy_source_closure_to_target"))
                target_verify = stack.enter_context(patch.object(stage0, "verify_target_store"))
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
            password_hash.assert_called_once_with()
            copy_store.assert_called_once_with(source)
            target_verify.assert_called_once_with(source)
            installer.assert_called_once_with(source)
            esp.assert_called_once()
            credentials.assert_called_once_with(path / "etc/shadow", "$6$test$hash")

    def test_password_bootstrap_never_overwrites_preexisting_hash(self):
        with tempfile.TemporaryDirectory() as td:
            shadow = Path(td) / "shadow"
            shadow.write_text("root:!:1:0:99999:7:::\nalex:$6$old$existing:1:0:99999:7:::\n")
            before = shadow.read_bytes()
            shadow_meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
            with patch.object(stage0, "validated_shadow_metadata", return_value=shadow_meta), \
                 patch.object(stage0, "output_hash") as hasher:
                with self.assertRaisesRegex(stage0.AdmissionError, "already has a password"):
                    stage0.credential_bootstrap(shadow, "$6$new$hash")
            self.assertEqual(shadow.read_bytes(), before)
            hasher.assert_not_called()

    def test_uefi_loader_entry_matches_evaluated_root_fstab(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            boot = root / "boot"
            efi = boot / "EFI/BOOT/BOOTX64.EFI"
            entry = boot / "loader/entries/nixos-generation-1.conf"
            efi.parent.mkdir(parents=True)
            entry.parent.mkdir(parents=True)
            efi.write_bytes(b"systemd-boot EFI image")
            (root / "etc").mkdir()
            (root / "etc/shadow").write_text("alex:!:1:0:99999:7:::\n")
            (boot / "EFI/nixos").mkdir(parents=True)
            kernel = boot / "EFI/nixos/stage0-linux.efi"
            initrd = boot / "EFI/nixos/stage0-initrd.efi"
            kernel.write_bytes(b"kernel-image")
            initrd.write_bytes(b"initrd-image")
            entry.write_text(
                "title NixOS Stage0\n"
                "linux /EFI/nixos/stage0-linux.efi\n"
                "initrd /EFI/nixos/stage0-initrd.efi\n"
                f"options init={stage0.SYSTEM}/init nomodeset root=fstab loglevel=4\n"
            )
            with patch.object(stage0, "NIX_ROOT", root):
                stage0.verify_installed_esp()
                good = entry.read_text()
                entry.write_text(good.replace("root=fstab", "root=/dev/sda1"))
                with self.assertRaisesRegex(stage0.AdmissionError, "root=fstab"):
                    stage0.verify_installed_esp()
                entry.write_text(good.replace(f"init={stage0.SYSTEM}/init", "init=/nix/store/tamper/init"))
                with self.assertRaisesRegex(stage0.AdmissionError, "init="):
                    stage0.verify_installed_esp()
                entry.write_text(good)
                initrd.unlink()
                with self.assertRaisesRegex(stage0.AdmissionError, "missing/empty"):
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

    def test_all_source_phases_use_only_same_pinned_oci_image(self):
        source = sealed_source()
        calls = []
        with patch.object(stage0, "host_cmd", side_effect=lambda *cmd: calls.append(cmd)), \
             patch.object(stage0, "output", return_value=sealed_nar_info()):
            stage0.verify_source_store(source)
            stage0.verify_install_namespace(source)
            stage0.copy_source_closure_to_target(source)
            stage0.run_container(source)
        self.assertEqual(len(calls), 4)
        for cmd in calls:
            self.assertEqual(cmd.count(stage0.SEALED_IMAGE), 1)
            self.assertIn("--pull=never", cmd)
            self.assertIn("--network=none", cmd)
            self.assertNotIn("type=volume", " ".join(cmd))
            self.assertNotIn(stage0.BUILD_VOLUME, " ".join(cmd))
            self.assertNotIn(stage0.NIX_IMAGE, " ".join(cmd))
            self.assertNotIn("--privileged", cmd)
            self.assertNotIn("/dev/disk/", " ".join(cmd))
        # A concurrent writer on the old Docker volume has no source access
        # in any command of the new verify/copy/privileged install pipeline.
        self.assertEqual(calls[-1][calls[-1].index("--entrypoint")+1], "/busybox")

    def test_oci_command_refuses_wrong_digest_and_mutable_volume(self):
        source = sealed_source()
        source["image"] = "sha256:" + "f"*64
        with self.assertRaisesRegex(stage0.AdmissionError, "unsealed"):
            stage0.verify_source_store(source)
        source = sealed_source()
        source["volume"] = stage0.BUILD_VOLUME
        with self.assertRaisesRegex(stage0.AdmissionError, "mutable"):
            stage0.run_container(source)

    def test_attestation_rejects_tampered_reviewed_head_before_docker(self):
        source = sealed_source()
        payload = {
            "schema_version": 1, "kind": "heim-pc-stage0-sealed-oci-source-v1",
            "image_id": stage0.SEALED_IMAGE,
            "original_nix_builder_image": stage0.NIX_IMAGE,
            "original_build_revision": stage0.BUILD_REV,
            "system_store": stage0.SYSTEM,
            "installer_store": stage0.INSTALLER,
            "util_linux_store": stage0.UTIL_LINUX,
            "system_nar_hash": stage0.SEALED_NAR[stage0.SYSTEM][0],
            "system_nar_size": stage0.SEALED_NAR[stage0.SYSTEM][1],
            "installer_nar_hash": stage0.SEALED_NAR[stage0.INSTALLER][0],
            "installer_nar_size": stage0.SEALED_NAR[stage0.INSTALLER][1],
            "util_linux_nar_hash": stage0.SEALED_NAR[stage0.UTIL_LINUX][0],
            "util_linux_nar_size": stage0.SEALED_NAR[stage0.UTIL_LINUX][1],
            "busybox_sha256": stage0.SEALED_BUSYBOX_SHA256,
            "source_prototype_report_sha256": stage0.SOURCE_PROTOTYPE_REPORT_SHA256,
            "source_scratch_report_sha256": stage0.SOURCE_SCRATCH_REPORT_SHA256,
            "reviewed_source_head": "f"*40,
            "reviewed_installer_script_sha256": source["script_sha256"],
            "independent_review_receipt_sha256": "1"*64,
        }
        with tempfile.TemporaryDirectory() as td:
            filename = Path(td) / "seal.json"
            filename.write_text(json.dumps(payload))
            st = filename.stat()
            parent_root = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            file_root = types.SimpleNamespace(st_mode=st.st_mode, st_uid=0,
                                              st_nlink=1, st_size=st.st_size)
            with patch.object(stage0, "SEALED_SOURCE_ATTESTATION", filename), \
                 patch.object(stage0.Path, "lstat", return_value=parent_root), \
                 patch.object(stage0.os, "fstat", return_value=file_root), \
                 patch.object(stage0, "output") as command:
                with self.assertRaisesRegex(stage0.AdmissionError, "provenance mismatch"):
                    stage0.require_immutable_install_source(source)
                command.assert_not_called()

    def test_attestation_rejects_wrong_image_id_before_docker(self):
        source = sealed_source()
        # The source image is pinned by code. A source-side digest override
        # must fail even if a synthetic sign-off file is otherwise present.
        source["image"] = "sha256:" + "0"*64
        with patch.object(stage0, "output") as command:
            with self.assertRaisesRegex(stage0.AdmissionError, "unsealed or mutable"):
                stage0.require_immutable_install_source(source)
            command.assert_not_called()

    def test_missing_attestation_never_snapshots_hardware(self):
        with tempfile.TemporaryDirectory() as td:
            source = sealed_source()
            with patch.object(stage0, "SEALED_SOURCE_ATTESTATION", Path(td)/"missing"), \
                 patch.object(stage0.Path, "lstat", return_value=types.SimpleNamespace(
                     st_mode=stat.S_IFDIR | 0o700, st_uid=0)), \
                 patch.object(stage0, "output") as docker, \
                 patch.object(stage0, "live_snapshot") as disk:
                with self.assertRaisesRegex(stage0.AdmissionError, "source seal missing"):
                    stage0.require_immutable_install_source(source)
                docker.assert_not_called()
                disk.assert_not_called()


    def test_independent_review_receipt_is_bound_to_exact_head_and_bytes(self):
        source = sealed_source()
        review = {
            "schema_version": 1,
            "kind": "heim-pc-stage0-source-security-review-v1",
            "source_head": source["revision"],
            "installer_script_sha256": source["script_sha256"],
            "image_id": stage0.SEALED_IMAGE,
            "disposition": "APPROVE_SOURCE_ONLY",
            "reviewer": "independent-test-reviewer",
            "review_url": "https://github.com/heimgewebe/heim-pc/pull/238#pullrequestreview-5609380329",
        }
        review_bytes = stage0.canonical(review)
        attestation = {
            "schema_version": 1, "kind": "heim-pc-stage0-sealed-oci-source-v1",
            "image_id": stage0.SEALED_IMAGE,
            "original_nix_builder_image": stage0.NIX_IMAGE,
            "original_build_revision": stage0.BUILD_REV,
            "system_store": stage0.SYSTEM, "installer_store": stage0.INSTALLER,
            "util_linux_store": stage0.UTIL_LINUX,
            "system_nar_hash": stage0.SEALED_NAR[stage0.SYSTEM][0],
            "system_nar_size": stage0.SEALED_NAR[stage0.SYSTEM][1],
            "installer_nar_hash": stage0.SEALED_NAR[stage0.INSTALLER][0],
            "installer_nar_size": stage0.SEALED_NAR[stage0.INSTALLER][1],
            "util_linux_nar_hash": stage0.SEALED_NAR[stage0.UTIL_LINUX][0],
            "util_linux_nar_size": stage0.SEALED_NAR[stage0.UTIL_LINUX][1],
            "busybox_sha256": stage0.SEALED_BUSYBOX_SHA256,
            "source_prototype_report_sha256": stage0.SOURCE_PROTOTYPE_REPORT_SHA256,
            "source_scratch_report_sha256": stage0.SOURCE_SCRATCH_REPORT_SHA256,
            "reviewed_source_head": source["revision"],
            "reviewed_installer_script_sha256": source["script_sha256"],
            "independent_review_receipt_sha256": stage0.digest(review_bytes),
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seal.json"
            path.write_bytes(stage0.canonical(attestation))
            review_path = path.with_name("stage0-independent-source-review-v1.json")
            review_path.write_bytes(review_bytes)
            # Test only: spoof ownership of disposable local test files.
            # A real production release must be issued by a root operator.
            st_a, st_b = path.stat(), review_path.stat()
            parent_meta = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
            meta = [types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                          st_nlink=1, st_size=st.st_size)
                    for st in (st_a, st_b)]
            def expected_output(*argv):
                if argv[1:3] == ("image", "inspect"):
                    return stage0.SEALED_IMAGE
                if argv[1:3] == ("run", "--rm"):
                    return stage0.SEALED_BUSYBOX_SHA256 + "  /busybox"
                raise AssertionError("unexpected OCI probe")
            with patch.object(stage0, "SEALED_SOURCE_ATTESTATION", path), \
                 patch.object(stage0.Path, "lstat", return_value=parent_meta), \
                 patch.object(stage0.os, "fstat", side_effect=meta + [meta[-1]]), \
                 patch.object(stage0, "output", side_effect=expected_output) as docker:
                stage0.require_immutable_install_source(source)
                self.assertEqual(docker.call_count, 2)
            # Changing only the review receipt must invalidate the copied
            # source seal before ANY Docker/image or disk access.
            review_path.write_bytes(review_bytes + b" ")
            with patch.object(stage0, "SEALED_SOURCE_ATTESTATION", path), \
                 patch.object(stage0.Path, "lstat", return_value=parent_meta), \
                 patch.object(stage0.os, "fstat", side_effect=meta), \
                 patch.object(stage0, "output") as docker:
                with self.assertRaisesRegex(stage0.AdmissionError, "receipt hash mismatch"):
                    stage0.require_immutable_install_source(source)
                docker.assert_not_called()

    def test_forged_review_receipt_digest_without_file_is_rejected(self):
        source = sealed_source()
        attestation = {
            "schema_version": 1, "kind": "heim-pc-stage0-sealed-oci-source-v1",
            "image_id": stage0.SEALED_IMAGE,
            "original_nix_builder_image": stage0.NIX_IMAGE,
            "original_build_revision": stage0.BUILD_REV,
            "system_store": stage0.SYSTEM, "installer_store": stage0.INSTALLER,
            "util_linux_store": stage0.UTIL_LINUX,
            "system_nar_hash": stage0.SEALED_NAR[stage0.SYSTEM][0],
            "system_nar_size": stage0.SEALED_NAR[stage0.SYSTEM][1],
            "installer_nar_hash": stage0.SEALED_NAR[stage0.INSTALLER][0],
            "installer_nar_size": stage0.SEALED_NAR[stage0.INSTALLER][1],
            "util_linux_nar_hash": stage0.SEALED_NAR[stage0.UTIL_LINUX][0],
            "util_linux_nar_size": stage0.SEALED_NAR[stage0.UTIL_LINUX][1],
            "busybox_sha256": stage0.SEALED_BUSYBOX_SHA256,
            "source_prototype_report_sha256": stage0.SOURCE_PROTOTYPE_REPORT_SHA256,
            "source_scratch_report_sha256": stage0.SOURCE_SCRATCH_REPORT_SHA256,
            "reviewed_source_head": source["revision"],
            "reviewed_installer_script_sha256": source["script_sha256"],
            "independent_review_receipt_sha256": "a"*64,
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "seal.json"
            path.write_bytes(stage0.canonical(attestation))
            st = path.stat()
            with patch.object(stage0, "SEALED_SOURCE_ATTESTATION", path), \
                 patch.object(stage0.Path, "lstat", return_value=types.SimpleNamespace(
                     st_mode=stat.S_IFDIR | 0o700, st_uid=0)), \
                 patch.object(stage0.os, "fstat", return_value=types.SimpleNamespace(
                     st_mode=stat.S_IFREG | 0o600, st_uid=0,
                     st_nlink=1, st_size=st.st_size)), \
                 patch.object(stage0, "output") as docker:
                with self.assertRaisesRegex(stage0.AdmissionError, "review receipt missing"):
                    stage0.require_immutable_install_source(source)
                docker.assert_not_called()

    def test_source_nar_metadata_tampering_fails_closed(self):
        source = sealed_source()
        info = json.loads(sealed_nar_info())
        info[stage0.INSTALLER]["narHash"] = "sha256-ATTACKER_FORGED_NAR="
        with patch.object(stage0, "host_cmd") as check, \
             patch.object(stage0, "output", return_value=json.dumps(info)):
            with self.assertRaisesRegex(stage0.AdmissionError, "NAR hash or size"):
                stage0.verify_source_store(source)
        check.assert_called_once()
        # A substitute exact Store path whose metadata differs is rejected
        # BEFORE a target install operation can begin.

    def test_source_nar_missing_entry_fails_closed(self):
        source = sealed_source()
        info = json.loads(sealed_nar_info())
        del info[stage0.UTIL_LINUX]
        with patch.object(stage0, "host_cmd") as check, \
             patch.object(stage0, "output", return_value=json.dumps(info)):
            with self.assertRaisesRegex(stage0.AdmissionError, "NAR entries"):
                stage0.verify_source_store(source)
        check.assert_called_once()

    def test_target_store_verification_is_recursive_content_check_before_installer(self):
        source = sealed_source()
        with patch.object(stage0, "host_cmd") as verify:
            stage0.verify_target_store(source)
        cmd = verify.call_args.args
        self.assertIn("local?root=/mnt", cmd)
        self.assertIn("--no-trust", cmd)
        self.assertIn("--recursive", cmd)
        self.assertIn(stage0.SYSTEM, cmd)
        self.assertIn("--pull=never", cmd)
        self.assertIn(stage0.SEALED_IMAGE, cmd)
        self.assertNotIn("type=volume", " ".join(cmd))
        self.assertNotIn(stage0.BUILD_VOLUME, " ".join(cmd))
        self.assertNotIn("--privileged", cmd)


if __name__ == "__main__":
    unittest.main()