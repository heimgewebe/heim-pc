"""Execute the production inventory filter against inert JSON, never devices."""
import os
import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILTER = ROOT / "nixos/system/modules/live-block-inventory.jq"


def fixture():
    return [
        {"filesystems": [
            {"target": "/", "source": "tmpfs", "fstype": "tmpfs", "maj:min": "0:20", "options": "rw"},
            {"target": "/iso", "source": "tmpfs", "fstype": "tmpfs", "maj:min": "0:21", "options": "rw"},
            {"target": "/nix/.ro-store", "source": "/dev/loop0", "fstype": "squashfs", "maj:min": "7:0", "options": "ro,relatime"},
            {"target": "/nix/store", "source": "overlay", "fstype": "overlay", "maj:min": "0:22", "options": "rw"},
        ]},
        {"blockdevices": [
            {"path": "/dev/loop0", "type": "loop", "maj:min": "7:0"},
            {"path": "/dev/sda", "type": "disk", "maj:min": "8:0"},
        ]},
        {"loopdevices": [{"name": "/dev/loop0", "back-file": "/iso/nix-store.squashfs"}]},
    ]


def evaluate(data):
    return subprocess.run(
        ["jq", "--compact-output", "--exit-status", "--slurp", "--from-file", str(FILTER)],
        input="\n".join(json.dumps(item) for item in data),
        text=True, capture_output=True, check=False,
    )


def test_ram_live_store_passes_and_physical_paths_are_not_exempt():
    result = evaluate(fixture())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["/dev/sda"]


@pytest.mark.parametrize("path,kind", [
    ("/dev/mmcblk0p1", "part"), ("/dev/mapper/root", "crypt"),
    ("/dev/dm-0", "lvm"), ("/dev/md0", "raid1"),
    ("/dev/unfamiliar", "future-device-type"), ("/dev/loop7", "loop"),
])
def test_device_classes_are_checked_without_prefix_allowlist(path, kind):
    data = fixture()
    data[1]["blockdevices"].append({"path": path, "type": kind, "maj:min": "250:7"})
    result = evaluate(data)
    assert result.returncode == 0, result.stderr
    assert path in json.loads(result.stdout)


@pytest.mark.parametrize("source,number", [
    ("/dev/mmcblk0p1", "179:1"), ("/dev/mapper/root[/@root]", "253:0"),
    ("/dev/loop7", "7:7"), ("UUID=not-a-device-name", "8:1"),
    ("/dev/mapper/root", "0:99"),
])
def test_any_unapproved_block_mount_fails(source, number):
    data = fixture()
    data[0]["filesystems"].append({"target": "/mnt", "source": source, "fstype": "btrfs", "maj:min": number, "options": "ro"})
    assert evaluate(data).returncode != 0


@pytest.mark.parametrize("index,key", [(0, "filesystems"), (1, "blockdevices"), (2, "loopdevices")])
def test_missing_or_malformed_inventory_never_means_empty_safe_inventory(index, key):
    for replacement in ({}, {key: None}, {key: "not-an-array"}, {key: [None]}):
        data = fixture()
        data[index] = replacement
        assert evaluate(data).returncode != 0


@pytest.mark.parametrize("index,key,field", [
    (0, "filesystems", "source"), (0, "filesystems", "maj:min"),
    (1, "blockdevices", "path"), (1, "blockdevices", "type"),
    (2, "loopdevices", "back-file"),
])
def test_incomplete_rows_fail(index, key, field):
    data = fixture()
    del data[index][key][0][field]
    assert evaluate(data).returncode != 0


@pytest.mark.parametrize("backing", ["/home/alex/disk.img", "/iso/../disk.img", "/iso/other.squashfs"])
def test_loop_name_alone_does_not_prove_ram_backing(backing):
    data = fixture()
    data[2]["loopdevices"][0]["back-file"] = backing
    assert evaluate(data).returncode != 0


def test_wrong_store_type_or_writeable_store_is_rejected():
    for key, value in [("fstype", "ext4"), ("options", "rw"), ("target", "/other")]:
        data = fixture()
        data[0]["filesystems"][2][key] = value
        assert evaluate(data).returncode != 0


def test_backing_file_source_and_no_physical_disk_are_valid():
    data = fixture()
    data[0]["filesystems"][2]["source"] = "/iso/nix-store.squashfs"
    data[1]["blockdevices"].pop()
    result = evaluate(data)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_malformed_json_and_missing_command_output_fail():
    assert evaluate(fixture()[:2]).returncode != 0
    result = subprocess.run(["jq", "-ces", "-f", str(FILTER)], input="{not json", text=True, capture_output=True)
    assert result.returncode != 0


@pytest.mark.parametrize("failure", ["findmnt", "lsblk", "losetup", "runuser", "id", "bad-json", ""])
def test_shell_observation_failures_stop_before_safety_pass(failure):
    data = fixture()
    data[1]["blockdevices"].pop()
    source = (ROOT / "nixos/system/modules/live-media.nix").read_text()
    start = source.index('      mount_inventory="$(findmnt')
    end = source.index("      # Keep the boot-safety path", start)
    script = source[start:end]
    script = script.replace("${./live-block-inventory.jq}", str(FILTER))
    script = script.replace("${liveUser}", "alex").replace("${pkgs.runtimeShell}", "/bin/sh")
    # Stub observations only. No real inventory, privilege drop or device read.
    prelude = '''
set -euo pipefail
failed=0
pass() { printf "PASS %s\\n" "$1"; }
fail() { printf "FAIL %s\\n" "$1"; failed=1; }
findmnt() { [ "$FAILURE" != findmnt ] || return 2; printf "%s" "$MOUNTS"; }
lsblk() { [ "$FAILURE" != lsblk ] || return 2; if [ "$FAILURE" = bad-json ]; then printf "{}"; else printf "%s" "$BLOCKS"; fi; }
losetup() { [ "$FAILURE" != losetup ] || return 2; printf "%s" "$LOOPS"; }
id() { [ "$FAILURE" != id ] || return 2; printf "audio video networkmanager"; }
runuser() { [ "$FAILURE" != runuser ]; }
'''
    result = subprocess.run(
        ["bash", "-c", prelude + script + 'exit "$failed"\n'],
        text=True, capture_output=True,
        env={"PATH": os.environ["PATH"], "FAILURE": failure,
             "MOUNTS": json.dumps(data[0]), "BLOCKS": json.dumps(data[1]), "LOOPS": json.dumps(data[2])},
    )
    assert (result.returncode == 0) == (failure == ""), result.stdout + result.stderr
    if failure:
        assert "PASS raw-block-devices-inaccessible-to-live-user" not in result.stdout
