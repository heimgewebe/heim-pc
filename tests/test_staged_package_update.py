from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "staged_package_update.py"
SPEC = importlib.util.spec_from_file_location("staged_package_update", SCRIPT)
assert SPEC and SPEC.loader
spu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(spu)


def _write_broker_evidence(
    root: Path,
    *,
    argv: list[str],
    stdout: str,
    request_id: str,
    timestamp_unix: int,
    peer_uid: int | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    value: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.BROKER_OUTPUT_EVIDENCE_KIND,
        "request_id": request_id,
        "reference_sha256": "1" * 64,
        "action": spu.BROKER_POWER_ACTION,
        "mode": "argv-json",
        "argv_sha256": spu._sha256_json(argv),
        "cwd_sha256": "2" * 64,
        "peer_uid": os.geteuid() if peer_uid is None else peer_uid,
        "peer_unit": spu.BROKER_PEER_UNIT,
        "returncode": 0,
        "timed_out": False,
        "stdout_sha256": spu._sha256_bytes(stdout.encode("utf-8")),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stdout_truncated": False,
        "timestamp_unix": timestamp_unix,
    }
    value["evidence_sha256"] = spu._sha256_json(value)
    path = root / f"{request_id}.json"
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    path.chmod(0o640)
    return path


def _allow_test_owned_broker_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    original = spu._validate_broker_output_evidence
    monkeypatch.setattr(
        spu,
        "_validate_broker_output_evidence",
        lambda *args, **kwargs: original(*args, **kwargs, expected_owner_uid=os.geteuid()),
    )


def test_run_uses_minimal_environment_and_ignores_caller_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        captured.update(kwargs)
        return Completed()

    attacker = {
        "APT_CONFIG": "/tmp/untrusted-apt.conf", "PATH": "/tmp/attacker",
        "HOME": "/tmp/attacker-home", "TMPDIR": "/tmp/attacker-tmp",
        "XDG_CONFIG_HOME": "/tmp/xdg", "PYTHONPATH": "/tmp/python",
        "LD_PRELOAD": "/tmp/evil.so", "SSL_CERT_FILE": "/tmp/evil-ca",
        "HTTPS_PROXY": "http://127.0.0.1:9", "GCONV_PATH": "/tmp/gconv",
        "LOCPATH": "/tmp/locale",
    }
    for key, value in attacker.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(spu.subprocess, "run", fake_run)
    spu._run(["/usr/bin/true"])
    env = captured["env"]
    assert isinstance(env, dict)
    assert env == spu._base_command_env()


def test_apt_options_pin_system_sources_and_authenticated_repositories(tmp_path: Path) -> None:
    values = spu._apt_options(tmp_path)[1::2]
    assert "Dir::Etc::sourcelist=/etc/apt/sources.list" in values
    assert "Dir::Etc::sourceparts=/etc/apt/sources.list.d" in values
    assert "APT::Get::AllowUnauthenticated=false" in values
    assert "Acquire::AllowInsecureRepositories=false" in values
    assert "Acquire::AllowDowngradeToInsecureRepositories=false" in values
    assert "Acquire::AllowWeakRepositories=false" in values


def test_source_baseline_includes_active_signed_by_keyrings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gpg = tmp_path / "vendor.gpg"
    asc = tmp_path / "vendor.asc"
    gpg.write_bytes(b"gpg-key")
    asc.write_text("armored-key")
    list_source = tmp_path / "vendor.list"
    list_source.write_text(f"deb [signed-by={gpg}] https://example.invalid stable main\n")
    deb822_source = tmp_path / "vendor.sources"
    deb822_source.write_text(
        "Types: deb\nURIs: https://example.invalid/other\nSuites: stable\n"
        f"Signed-By: {asc}\n"
    )
    patterns = (str(list_source), str(deb822_source))
    monkeypatch.setattr(spu, "APT_SOURCE_FILE_PATTERNS", patterns)
    monkeypatch.setattr(spu, "APT_SOURCE_PATTERNS", patterns)
    records = spu._source_config_records()
    record_paths = {item["path"] for item in records}
    assert str(gpg) in record_paths
    assert str(asc) in record_paths
    baseline = records
    asc.write_text("rotated-armored-key")
    with pytest.raises(spu.PlanError, match="source/key configuration changed"):
        spu._validate_source_config(baseline)


def test_source_baseline_rejects_trusted_yes_bypass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "untrusted.list"
    source.write_text("deb [trusted=yes] https://example.invalid stable main\n")
    patterns = (str(source),)
    monkeypatch.setattr(spu, "APT_SOURCE_FILE_PATTERNS", patterns)
    monkeypatch.setattr(spu, "APT_SOURCE_PATTERNS", patterns)
    with pytest.raises(spu.PlanError, match="trusted=yes"):
        spu._source_config_records()


def test_apt_update_fails_closed_on_any_index_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        stdout = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n" if "-s" in argv else ""
        return {"argv": argv, "returncode": 0, "stdout": stdout, "stderr": ""}

    monkeypatch.setattr(spu, "_run", fake_run)
    policy = {
        "apt": {
            "enabled": True,
            "max_packages": 10,
            "max_download_bytes": 1024,
            "sensitive_prefixes": [],
        }
    }
    result = spu._stage_apt(tmp_path / "stage", policy, os.geteuid())
    assert result["packages"] == []
    assert calls[0][-3:] == ["-o", "APT::Update::Error-Mode=any", "update"]


def test_parse_apt_print_uris_requires_supported_strong_hash() -> None:
    for algorithm, length in (("SHA256", 64), ("SHA512", 128)):
        digest = "a" * length
        text = f"'https://example.invalid/pkg.deb' pkg.deb 123 {algorithm}:{digest}\n"
        assert spu.parse_apt_print_uris(text) == [{
            "repository_uri_sha256": spu._sha256_bytes(b"https://example.invalid/pkg.deb"),
            "repository_uri_basename": "pkg.deb",
            "repository_filename": "pkg.deb",
            "repository_size": 123,
            "repository_hash_algorithm": algorithm,
            "repository_hash": digest,
        }]
    for weak in ("MD5Sum:deadbeef", "SHA1:" + "a" * 40):
        with pytest.raises(spu.PlanError, match="supported strong SHA256/SHA512"):
            spu.parse_apt_print_uris(f"'https://example.invalid/pkg.deb' pkg.deb 123 {weak}")
    with pytest.raises(spu.PlanError, match="supported strong SHA256/SHA512"):
        spu.parse_apt_print_uris("'https://example.invalid/pkg.deb' pkg.deb 123 SHA256:deadbeef")


def test_parse_apt_cache_show_sha256_binds_exact_candidate_and_artifact() -> None:
    digest = "d" * 64
    candidate = {"name": "curl", "version": "2.0", "arch": "amd64"}
    text = (
        "Package: curl\nVersion: 1.0\nArchitecture: amd64\n"
        "Filename: pool/curl.deb\nSize: 123\nSHA256: " + "a" * 64 + "\n\n"
        "Package: curl\nVersion: 2.0\nArchitecture: amd64\n"
        "Filename: pool/main/c/curl/curl.deb\nSize: 123\nSHA256: " + digest + "\n"
        "Description: ignored\n continuation ignored\n\n"
    )
    assert spu.parse_apt_cache_show_sha256(
        text, candidate, repository_uri_basename="curl.deb", repository_size=123
    ) == digest
    with pytest.raises(spu.PlanError, match="exactly one SHA-256"):
        spu.parse_apt_cache_show_sha256(
            text, candidate, repository_uri_basename="other.deb", repository_size=123
        )


def test_apt_repository_record_binds_signed_sha256_when_print_uris_uses_sha512(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sha256 = "a" * 64
    sha512 = "b" * 128
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        if argv[0] == "/usr/bin/apt-get":
            return {
                "argv": argv, "returncode": 0, "stderr": "",
                "stdout": f"'https://example.invalid/bash.deb' bash.deb 123 SHA512:{sha512}\n",
            }
        if argv[0] == "/usr/bin/apt-cache":
            return {
                "argv": argv, "returncode": 0, "stderr": "",
                "stdout": (
                    "Package: bash\nVersion: 2.0\nArchitecture: amd64\n"
                    "Filename: pool/bash.deb\nSize: 123\nSHA256: " + sha256 + "\n\n"
                ),
            }
        raise AssertionError(argv)

    monkeypatch.setattr(spu, "_run", fake_run)
    record = spu._apt_repository_record([], {"name": "bash", "version": "2.0", "arch": "amd64"})
    assert record["repository_hash_algorithm"] == "SHA512"
    assert record["repository_hash"] == sha512
    assert record["repository_sha256"] == sha256
    assert calls[1][-2:] == ["show", "bash:amd64=2.0"]


def test_apt_repository_record_matches_epoch_candidate_by_uri_basename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sha256 = "a" * 64
    sha512 = "b" * 128

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        if argv[0] == "/usr/bin/apt-get":
            return {
                "argv": argv, "returncode": 0, "stderr": "",
                "stdout": (
                    "'https://example.invalid/pool/main/b/bolt/bolt-20_20.1.8-0ubuntu1_amd64.deb' "
                    f"'bolt-20_1%3a20.1.8-0ubuntu1_amd64.deb' 123 SHA512:{sha512}\n"
                ),
            }
        if argv[0] == "/usr/bin/apt-cache":
            return {
                "argv": argv, "returncode": 0, "stderr": "",
                "stdout": (
                    "Package: bolt-20\nVersion: 1:20.1.8-0ubuntu1\nArchitecture: amd64\n"
                    "Filename: pool/main/b/bolt/bolt-20_20.1.8-0ubuntu1_amd64.deb\n"
                    "Size: 123\nSHA256: " + sha256 + "\n\n"
                ),
            }
        raise AssertionError(argv)

    monkeypatch.setattr(spu, "_run", fake_run)
    record = spu._apt_repository_record(
        [], {"name": "bolt-20", "version": "1:20.1.8-0ubuntu1", "arch": "amd64"}
    )
    assert record["repository_filename"] == "bolt-20_1%3a20.1.8-0ubuntu1_amd64.deb"
    assert record["repository_uri_basename"] == "bolt-20_20.1.8-0ubuntu1_amd64.deb"
    assert record["repository_sha256"] == sha256


def test_stage_apt_uses_authenticated_repository_sha256_as_plan_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"signed-repository-deb"
    sha256 = spu._sha256_bytes(payload)
    sha512 = hashlib.sha512(payload).hexdigest()
    candidate = {"name": "curl", "version": "new", "arch": "amd64"}
    simulation = "Inst curl [old] (new Repo [amd64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"

    def fake_run(argv: list[str], **kwargs: object) -> dict[str, object]:
        if argv[-1] == "update":
            return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}
        if "-s" in argv:
            return {"argv": argv, "returncode": 0, "stdout": simulation, "stderr": ""}
        if argv[0] == "/usr/bin/apt-get" and "download" in argv and "--print-uris" not in argv:
            cwd = Path(str(kwargs["cwd"]))
            (cwd / "curl.deb").write_bytes(payload)
            return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}
        raise AssertionError(argv)

    monkeypatch.setattr(spu, "_run", fake_run)
    monkeypatch.setattr(spu, "_apt_repository_record", lambda options, current: {
        "repository_size": len(payload),
        "repository_hash_algorithm": "SHA512",
        "repository_hash": sha512,
        "repository_sha256": sha256,
        "repository_manifest_sha256": "b" * 64,
        "repository_uri_sha256": "c" * 64,
        "repository_uri_basename": "curl.deb",
        "repository_filename": "curl.deb",
    })
    monkeypatch.setattr(
        spu, "_deb_field",
        lambda path, field: {"Package": "curl", "Version": "new", "Architecture": "amd64"}[field],
    )
    monkeypatch.setattr(spu, "_deb_reboot_marker_capable", lambda path, uid: False)
    policy = {
        "apt": {
            "enabled": True, "max_packages": 10, "max_download_bytes": 1024 * 1024,
            "sensitive_prefixes": [],
        }
    }
    result = spu._stage_apt(tmp_path / "stage", policy, os.geteuid())
    assert len(result["packages"]) == 1
    artifact = result["packages"][0]
    assert artifact["sha256"] == sha256
    assert artifact["repository_sha256"] == sha256
    assert artifact["repository_hash_algorithm"] == "SHA512"
    assert artifact["repository_hash"] == sha512


def test_stage_apt_enforces_authenticated_byte_cap_before_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    simulation = "Inst curl [old] (new Repo [amd64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        if argv[-1] == "update":
            return {"argv": argv, "returncode": 0, "stdout": "", "stderr": ""}
        if "-s" in argv:
            return {"argv": argv, "returncode": 0, "stdout": simulation, "stderr": ""}
        if "--print-uris" in argv:
            return {"argv": argv, "returncode": 0, "stdout": "'https://example.invalid/curl.deb' curl.deb 2048 SHA256:" + "a" * 64 + "\n", "stderr": ""}
        if argv[0] == "/usr/bin/apt-cache":
            return {
                "argv": argv, "returncode": 0, "stderr": "",
                "stdout": (
                    "Package: curl\nVersion: new\nArchitecture: amd64\n"
                    "Filename: pool/curl.deb\nSize: 2048\nSHA256: " + "a" * 64 + "\n\n"
                ),
            }
        raise AssertionError(f"unexpected actual download: {argv}")

    monkeypatch.setattr(spu, "_run", fake_run)
    policy = {"apt": {"enabled": True, "max_packages": 10, "max_download_bytes": 1024, "sensitive_prefixes": []}}
    with pytest.raises(spu.PlanError, match="before download"):
        spu._stage_apt(tmp_path / "stage", policy, os.geteuid())
    assert any("--print-uris" in argv for argv in calls)
    assert not any("download" in argv and "--print-uris" not in argv for argv in calls)


def test_plan_id_rejects_root_stage_escape() -> None:
    assert spu._validate_plan_id("20260826T194332Z-1dedf2da5503") == "20260826T194332Z-1dedf2da5503"
    for value in ("../../etc", "plan-id", "20260826T194332Z-../../etc", "/tmp/evil"):
        with pytest.raises(spu.PlanError, match="plan_id"):
            spu._validate_plan_id(value)


def test_privileged_plan_policy_must_be_canonical(tmp_path: Path) -> None:
    alternate = tmp_path / "package-update-policy.v1.json"
    alternate.write_bytes((ROOT / "config" / "package-update-policy.v1.json").read_bytes())
    with pytest.raises(spu.PlanError, match="canonical repository policy"):
        spu._require_canonical_policy_path(alternate)
    assert spu._require_canonical_policy_path(ROOT / "config" / "package-update-policy.v1.json") == (ROOT / "config" / "package-update-policy.v1.json").resolve()


def test_stage_artifact_path_rejects_absolute_and_parent_escape(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    parent = stage / "apt" / "debs"
    with pytest.raises(spu.PlanError, match="escapes"):
        spu._stage_artifact_path(stage, "/tmp/evil.deb", parent)
    with pytest.raises(spu.PlanError, match="escapes"):
        spu._stage_artifact_path(stage, "apt/debs/../../evil.deb", parent)


def test_apt_provenance_revalidation_rejects_forged_deb_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stage = tmp_path / "stage"
    deb_dir = stage / "apt" / "debs"
    deb_dir.mkdir(parents=True)
    artifact = deb_dir / "curl.deb"
    artifact.write_bytes(b"forged")
    digest = "a" * 64
    item = {
        "name": "curl", "version": "new", "arch": "amd64", "package": "curl",
        "relative_path": "apt/debs/curl.deb", "size": len(b"forged"),
        "sha256": digest,
        "repository_size": 123, "repository_hash_algorithm": "SHA256", "repository_hash": digest,
        "repository_sha256": digest,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64,
        "sensitive": False,
    }
    plan = {"apt": {"enabled": True, "packages": [item]}}
    policy = {"apt": {
        "enabled": True, "max_packages": 10, "max_download_bytes": 1024 * 1024,
        "sensitive_prefixes": [],
    }}
    monkeypatch.setattr(spu, "_apt_update_and_candidates", lambda *args: ([], {}, {}, [{"name": "curl", "version": "new", "arch": "amd64"}]))
    monkeypatch.setattr(spu, "_apt_repository_record", lambda options, candidate: {
        "repository_size": 123, "repository_hash_algorithm": "SHA256", "repository_hash": digest,
        "repository_sha256": digest,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64,
        "repository_filename": "curl.deb",
    })
    monkeypatch.setattr(spu, "_deb_field", lambda path, field: {"Package": "curl", "Version": "new", "Architecture": "amd64"}[field])
    with pytest.raises(spu.PlanError, match="freshly authenticated repository metadata"):
        spu._revalidate_apt_provenance(stage, plan, policy, os.geteuid())


def test_apt_revalidation_rejects_plan_hash_not_bound_to_signed_repository_sha256(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authentic_sha256 = "a" * 64
    attacker_sha256 = "b" * 64
    sha512 = "c" * 128
    item = {
        "name": "bash", "version": "new", "arch": "amd64",
        "sha256": attacker_sha256,
        "repository_size": 123,
        "repository_hash_algorithm": "SHA512",
        "repository_hash": sha512,
        "repository_sha256": authentic_sha256,
        "repository_manifest_sha256": "d" * 64,
        "repository_uri_sha256": "e" * 64,
    }
    plan = {"apt": {"enabled": True, "packages": [item]}}
    policy = {"apt": {"enabled": True, "max_download_bytes": 1024 * 1024, "sensitive_prefixes": []}}
    monkeypatch.setattr(
        spu, "_apt_update_and_candidates",
        lambda *args: ([], {}, {}, [{"name": "bash", "version": "new", "arch": "amd64"}]),
    )
    monkeypatch.setattr(spu, "_apt_repository_record", lambda options, candidate: {
        "repository_size": 123,
        "repository_hash_algorithm": "SHA512",
        "repository_hash": sha512,
        "repository_sha256": authentic_sha256,
        "repository_manifest_sha256": "d" * 64,
        "repository_uri_sha256": "e" * 64,
    })
    with pytest.raises(spu.PlanError, match="plan SHA-256 differs from signed repository SHA-256"):
        spu._revalidate_apt_provenance(tmp_path / "stage", plan, policy, os.geteuid())


def test_apt_provenance_revalidation_rejects_forged_sensitive_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "a" * 64
    item = {
        "name": "linux-image-generic", "version": "new", "arch": "amd64",
        "sha256": digest,
        "repository_size": 123, "repository_hash_algorithm": "SHA256", "repository_hash": digest,
        "repository_sha256": digest,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64,
        "sensitive": False,
    }
    plan = {"apt": {"enabled": True, "packages": [item]}}
    policy = {"apt": {
        "enabled": True, "max_download_bytes": 1024 * 1024,
        "sensitive_prefixes": ["linux-", "systemd", "nvidia-"],
    }}
    monkeypatch.setattr(
        spu, "_apt_update_and_candidates",
        lambda *args: ([], {}, {}, [{"name": "linux-image-generic", "version": "new", "arch": "amd64"}]),
    )
    monkeypatch.setattr(spu, "_apt_repository_record", lambda options, candidate: {
        "repository_size": 123, "repository_hash_algorithm": "SHA256", "repository_hash": digest,
        "repository_sha256": digest,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64,
    })
    with pytest.raises(spu.PlanError, match="sensitive-package classification"):
        spu._revalidate_apt_provenance(tmp_path / "stage", plan, policy, os.geteuid())


def test_snap_provenance_requires_current_pending_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    upper = spu._snap_size_upper_bound_bytes("1MB")
    plan = {"snap": {
        "enabled": True,
        "packages": [{"name": "core22", "version": "new", "revision": "2", "size_upper_bound_bytes": upper}],
        "download_bytes": 0, "declared_upper_bound_bytes": upper + 1024,
    }}
    policy = {"snap": {"enabled": True, "max_snaps": 10, "max_download_bytes": 10 * 1024 * 1024, "max_assertion_bytes": 1024}}
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: {
        "argv": argv, "returncode": 0,
        "stdout": "Name Version Rev Size Publisher Notes\ncore22 newer 3 1MB canonical** base\n", "stderr": "",
    })
    with pytest.raises(spu.PlanError, match="pending refresh set changed"):
        spu._revalidate_snap_provenance(tmp_path / "stage", plan, policy, os.geteuid())


def test_snap_provenance_enforces_max_snaps_during_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = {"snap": {"enabled": True, "packages": []}}
    policy = {"snap": {
        "enabled": True, "max_snaps": 1, "max_download_bytes": 10 * 1024 * 1024,
        "max_assertion_bytes": 1024,
    }}
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: {
        "argv": argv, "returncode": 0,
        "stdout": (
            "Name Version Rev Size Publisher Notes\n"
            "core22 newer 3 1MB canonical** base\n"
            "snapd newer 4 1MB canonical** snapd\n"
        ),
        "stderr": "",
    })
    with pytest.raises(spu.PlanError, match="candidate count 2 exceeds policy limit during verification"):
        spu._revalidate_snap_provenance(tmp_path / "stage", plan, policy, os.geteuid())


def test_snap_provenance_rejects_staged_bytes_not_from_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stage = tmp_path / "stage"
    snap_dir = stage / "snap"
    snap_dir.mkdir(parents=True)
    staged_snap = snap_dir / "core22_2.snap"
    staged_assert = snap_dir / "core22_2.assert"
    staged_snap.write_bytes(b"forged-snap")
    staged_assert.write_bytes(b"forged-assertion")
    upper = spu._snap_size_upper_bound_bytes("1MB")
    assertion_cap = 1024
    item = {
        "name": "core22", "version": "new", "revision": "2", "baseline_revision": "1",
        "size_upper_bound_bytes": upper,
        "snap_relative_path": "snap/core22_2.snap",
        "snap_sha256": spu._sha256_file(staged_snap), "snap_size": staged_snap.stat().st_size,
        "assert_relative_path": "snap/core22_2.assert",
        "assert_sha256": spu._sha256_file(staged_assert), "assert_size": staged_assert.stat().st_size,
    }
    actual = staged_snap.stat().st_size + staged_assert.stat().st_size
    plan = {"snap": {
        "enabled": True, "packages": [item], "download_bytes": actual,
        "declared_upper_bound_bytes": upper + assertion_cap,
    }}
    policy = {"snap": {
        "enabled": True, "max_snaps": 10, "max_download_bytes": 10 * 1024 * 1024, "max_assertion_bytes": assertion_cap,
    }}

    def fake_run(argv: list[str], **kwargs: object) -> dict[str, object]:
        if argv[:3] == ["/usr/bin/snap", "refresh", "--list"]:
            return {"argv": argv, "returncode": 0, "stdout": "Name Version Rev Size Publisher Notes\ncore22 new 2 1MB canonical** base\n", "stderr": ""}
        raise AssertionError(argv)

    def fake_quota_download(target: Path, **kwargs: object) -> dict[str, object]:
        basename = str(kwargs["basename"]); (target / f"{basename}.snap").write_bytes(b"store-snap"); (target / f"{basename}.assert").write_bytes(b"store-assertion")
        return {"argv": ["quota"], "returncode": 0, "stdout": "fetched", "stderr": ""}

    monkeypatch.setattr(spu, "_run", fake_run)
    monkeypatch.setattr(spu, "_snap_quota_download", fake_quota_download)
    with pytest.raises(spu.PlanError, match="freshly downloaded Store artifact"):
        spu._revalidate_snap_provenance(stage, plan, policy, os.geteuid())


def test_snap_provenance_accepts_byteidentical_store_redownload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stage = tmp_path / "stage"
    snap_dir = stage / "snap"
    snap_dir.mkdir(parents=True)
    staged_snap = snap_dir / "core22_2.snap"
    staged_assert = snap_dir / "core22_2.assert"
    staged_snap.write_bytes(b"store-snap")
    staged_assert.write_bytes(b"store-assertion")
    upper = spu._snap_size_upper_bound_bytes("1MB")
    assertion_cap = 1024
    item = {
        "name": "core22", "version": "new", "revision": "2", "baseline_revision": "1",
        "size_upper_bound_bytes": upper,
        "snap_relative_path": "snap/core22_2.snap",
        "snap_sha256": spu._sha256_file(staged_snap), "snap_size": staged_snap.stat().st_size,
        "assert_relative_path": "snap/core22_2.assert",
        "assert_sha256": spu._sha256_file(staged_assert), "assert_size": staged_assert.stat().st_size,
    }
    actual = staged_snap.stat().st_size + staged_assert.stat().st_size
    plan = {"snap": {
        "enabled": True, "packages": [item], "download_bytes": actual,
        "declared_upper_bound_bytes": upper + assertion_cap,
    }}
    policy = {"snap": {
        "enabled": True, "max_snaps": 10, "max_download_bytes": 10 * 1024 * 1024, "max_assertion_bytes": assertion_cap,
    }}

    def fake_run(argv: list[str], **kwargs: object) -> dict[str, object]:
        if argv[:3] == ["/usr/bin/snap", "refresh", "--list"]:
            return {"argv": argv, "returncode": 0, "stdout": "Name Version Rev Size Publisher Notes\ncore22 new 2 1MB canonical** base\n", "stderr": ""}
        raise AssertionError(argv)

    def fake_quota_download(target: Path, **kwargs: object) -> dict[str, object]:
        basename = str(kwargs["basename"]); (target / f"{basename}.snap").write_bytes(b"store-snap"); (target / f"{basename}.assert").write_bytes(b"store-assertion")
        return {"argv": ["quota"], "returncode": 0, "stdout": "fetched", "stderr": ""}

    monkeypatch.setattr(spu, "_run", fake_run)
    monkeypatch.setattr(spu, "_snap_quota_download", fake_quota_download)
    spu._revalidate_snap_provenance(stage, plan, policy, os.geteuid())


def test_parse_apt_simulation_keeps_exact_identity() -> None:
    text = "\n".join(
        [
            "Inst curl [7.81.0-1ubuntu1.25] (7.81.0-1ubuntu1.27 Ubuntu:22.04/jammy-security [amd64])",
            "Inst libssl3:i386 [3.0.2-0ubuntu1.26] (3.0.2-0ubuntu1.29 Ubuntu:22.04/jammy-security [i386])",
            "Conf curl (7.81.0-1ubuntu1.27 Ubuntu:22.04/jammy-security [amd64])",
            "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
        ]
    )
    assert spu.parse_apt_simulation(text) == [
        {"name": "curl", "version": "7.81.0-1ubuntu1.27", "arch": "amd64"},
        {"name": "libssl3:i386", "version": "3.0.2-0ubuntu1.29", "arch": "i386"},
    ]


def test_parse_apt_simulation_rejects_unparsed_inst_row() -> None:
    with pytest.raises(spu.PlanError, match="unexpected apt simulation Inst row"):
        spu.parse_apt_simulation("Inst curl malformed solver output\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")


def test_parse_apt_simulation_rejects_mixed_partial_parse() -> None:
    text = "\n".join([
        "Inst curl [old] (new Ubuntu:22.04/jammy [amd64])",
        "Inst second-package output-format-drift",
        "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
    ])
    with pytest.raises(spu.PlanError, match="second-package"):
        spu.parse_apt_simulation(text)


def test_parse_apt_simulation_rejects_prefixed_inst_row() -> None:
    text = "\x1b[31mInst curl [old] (new Repo [amd64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
    with pytest.raises(spu.PlanError, match="unexpected apt simulation Inst row"):
        spu.parse_apt_simulation(text)


def test_parse_apt_simulation_requires_summary_count_match() -> None:
    text = "Inst curl [old] (new Repo [amd64])\n2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
    with pytest.raises(spu.PlanError, match="summary declares 2"):
        spu.parse_apt_simulation(text)


def test_parse_snap_refresh_list_ignores_headers_and_prose() -> None:
    text = """Name Version Rev Size Publisher Notes
core22 20260410 2437 77.6MB canonical** base
gnome-46-2404 0+git.b31ceab 164 644MB canonical** -
"""
    assert spu.parse_snap_refresh_list(text) == [
        {
            "name": "core22", "version": "20260410", "revision": "2437",
            "size_upper_bound_bytes": spu._snap_size_upper_bound_bytes("77.6MB"),
        },
        {
            "name": "gnome-46-2404", "version": "0+git.b31ceab", "revision": "164",
            "size_upper_bound_bytes": spu._snap_size_upper_bound_bytes("644MB"),
        },
    ]
    assert spu._snap_size_upper_bound_bytes("77.6MB") > 77_600_000
    with pytest.raises(spu.PlanError, match="unexpected snap size"):
        spu._snap_size_upper_bound_bytes("unknown")


def test_stage_snap_enforces_declared_byte_cap_before_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    def fake_run(argv: list[str], **kwargs: object) -> dict[str, object]:
        calls.append(argv)
        if argv[:3] == ["/usr/bin/snap", "refresh", "--list"]:
            return {"argv": argv, "returncode": 0, "stdout": "Name Version Rev Size Publisher Notes\ncore22 new 2 2GB canonical** base\n", "stderr": ""}
        raise AssertionError(f"download should not start: {argv}")
    monkeypatch.setattr(spu, "_run", fake_run)
    policy = {"snap": {
        "enabled": True, "max_snaps": 10, "max_download_bytes": 1024 * 1024,
        "max_assertion_bytes": 1024, "download_quota_mode": "userns-pid-tmpfs-bwrap-ro-root",
    }}
    with pytest.raises(spu.PlanError, match="before download"):
        spu._stage_snap(tmp_path / "stage", policy, os.geteuid())
    assert not any(argv[:2] == ["/usr/bin/snap", "download"] for argv in calls)


def test_snap_quota_argv_is_userns_mount_isolated(tmp_path: Path) -> None:
    output = (tmp_path / "snap").resolve(); mountpoint = output / ".quota-test"
    argv = spu._snap_quota_argv(output, mountpoint, name="core22", revision="2", basename="core22_2", snap_cap=2048, assertion_cap=1024)
    assert argv[:4] == ["/usr/bin/unshare", "--user", "--map-root-user", "--mount"]
    for flag in ("--pid", "--fork", "--kill-child=KILL", "--mount-proc"):
        assert flag in argv
    python_index = argv.index("/usr/bin/python3")
    assert argv[python_index + 1] == "-I"
    assert "__snap-quota-worker" in argv
    assert argv[-2:] == ["2048", "1024"] and "/usr/bin/snap" not in argv


def test_cli_shebang_requires_isolated_python() -> None:
    first_line = SCRIPT.read_text().splitlines()[0]
    assert first_line == "#!/usr/bin/python3 -I"


def test_stage_snap_uses_hard_quota_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    def fake_run(argv: list[str], **kwargs: object) -> dict[str, object]:
        if argv[:3] == ["/usr/bin/snap", "refresh", "--list"]: return {"argv": argv, "returncode": 0, "stdout": "Name Version Rev Size Publisher Notes\ncore22 new 2 1MB canonical** base\n", "stderr": ""}
        if argv[:2] == ["/usr/bin/snap", "list"]: return {"argv": argv, "returncode": 0, "stdout": "Name Version Rev Tracking Publisher Notes\ncore22 old 1 latest/stable canonical** base\n", "stderr": ""}
        raise AssertionError(argv)
    def fake_quota(target: Path, **kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs)); basename = str(kwargs["basename"]); (target / f"{basename}.snap").write_bytes(b"snap"); (target / f"{basename}.assert").write_bytes(b"assert"); return {"argv": ["quota"], "returncode": 0, "stdout": "fetched", "stderr": ""}
    monkeypatch.setattr(spu, "_run", fake_run); monkeypatch.setattr(spu, "_snap_quota_download", fake_quota)
    policy = {"snap": {"enabled": True, "max_snaps": 10, "max_download_bytes": 10 * 1024 * 1024, "max_assertion_bytes": 1024, "download_quota_mode": "userns-pid-tmpfs-bwrap-ro-root"}}
    result = spu._stage_snap(tmp_path / "stage", policy, os.geteuid())
    assert len(calls) == 1 and calls[0]["name"] == "core22" and calls[0]["assertion_cap"] == 1024 and calls[0]["snap_cap"] == spu._snap_size_upper_bound_bytes("1MB")
    assert result["download_bytes"] == len(b"snap") + len(b"assert")


def test_policy_requires_snap_hard_quota_mode(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text()); policy["snap"]["download_quota_mode"] = "postcheck-only"; path = tmp_path / "policy.json"; path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="download_quota_mode"): spu.load_policy(path)
    policy["snap"]["download_quota_mode"] = "userns-pid-tmpfs-bwrap-ro-root"; policy["safety"]["require_snap_download_hard_quota"] = False; path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_snap_download_hard_quota"): spu.load_policy(path)
    policy["safety"]["require_snap_download_hard_quota"] = True; policy["safety"]["require_authenticated_apt_preflight_completion"] = False; path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_authenticated_apt_preflight_completion"): spu.load_policy(path)
    policy["safety"]["require_authenticated_apt_preflight_completion"] = True; policy["safety"]["require_authenticated_apply_completion_evidence"] = False; path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_authenticated_apply_completion_evidence"): spu.load_policy(path)


def test_broker_evidence_requires_group_read_only_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence_root = tmp_path / "broker-evidence"; monkeypatch.setattr(spu, "BROKER_OUTPUT_EVIDENCE_ROOT", evidence_root); _allow_test_owned_broker_evidence(monkeypatch)
    argv = ["/usr/bin/stat", "-f", "-c", "%a:%S", "/var/lib/heim-pc/package-update-stages"]; stdout = "100:4096\n"
    path = _write_broker_evidence(evidence_root, argv=argv, stdout=stdout, request_id="9" * 32, timestamp_unix=int(spu.time.time()))
    spu._validate_broker_output_evidence(path, expected_argv=argv, stdout_text=stdout, expected_peer_uid=os.geteuid(), not_before_unix=0, max_age_seconds=600)
    path.chmod(0o644)
    with pytest.raises(spu.PlanError, match="file is not trusted"): spu._validate_broker_output_evidence(path, expected_argv=argv, stdout_text=stdout, expected_peer_uid=os.geteuid(), not_before_unix=0, max_age_seconds=600)


def test_plan_hash_excludes_only_hash_field() -> None:
    plan = {"schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "x", "value": 7}
    digest = spu._plan_digest(plan)
    plan["plan_sha256"] = digest
    assert spu._plan_digest(plan) == digest
    plan["value"] = 8
    assert spu._plan_digest(plan) != digest


def test_root_commands_are_networkless_and_never_execute_user_code(tmp_path: Path) -> None:
    policy = {
        "staging": {
            "root_root": "/var/lib/heim-pc/package-update-stages",
            "runtime_capture_root": "/run/heim-pc-package-update-captures",
            "root_stage_safety_margin_bytes": 1000,
        },
    }
    stage = tmp_path / "stage"
    apt = {
        "packages": [
            {
                "relative_path": "apt/debs/000-curl-amd64-deadbeef.deb",
                "sha256": "a" * 64,
                "size": 123,
            }
        ]
    }
    snap = {
        "packages": [
            {
                "assert_relative_path": "snap/core22_2437.assert",
                "assert_size": 10,
                "snap_relative_path": "snap/core22_2437.snap",
                "snap_size": 20,
            }
        ]
    }
    plan_id = "20260826T194332Z-1dedf2da5503"
    commands = spu._root_commands(plan_id, stage, policy, apt, snap)
    for withheld in (
        "prepare_argv", "copy_apt_argv", "copy_snap_argv",
        "hash_apt_argv", "hash_snap_argv", "apt_apply_preflight_argv",
        "apt_apply_argv", "snap_apply_argvs",
    ):
        assert withheld not in commands
    assert commands["capacity_readback_required"] is True
    assert commands["apply_readback_required"] is True
    plan = {"plan_id": plan_id, "stage_path": str(stage), "root_commands": commands, "apt": apt, "snap": snap}
    copy_commands = spu._copy_commands(plan, policy)
    apt_preflight = spu._apt_apply_preflight_argv(plan)
    assert "apt_apply_preflight_argv" not in copy_commands
    apply_commands = spu._apply_commands(plan, policy)
    apt_apply = apply_commands["apt_apply_argv"]
    root_debs = "/var/lib/heim-pc/package-update-stages/20260826T194332Z-1dedf2da5503/debs"
    root_deb = f"{root_debs}/000-curl-amd64-deadbeef.deb"
    assert apt_preflight == [
        "/usr/bin/dpkg", "--simulate", "--refuse-downgrade", "--force-confold",
        "--install", root_deb,
    ]
    assert apt_apply == [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        "--unit=heim-pc-package-update-20260826T194332Z-1dedf2da5503.service",
        "--property=Type=exec",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateMounts=yes",
        "--property=PrivateNetwork=yes",
        "--property=BindPaths=/run/heim-pc-package-update-captures/20260826T194332Z-1dedf2da5503:/run",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=BindReadOnlyPaths=/dev/null:/run/systemd/private /dev/null:/run/dbus/system_bus_socket",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes",
        "--property=PrivateDevices=yes",
        "--property=RestrictNamespaces=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=LockPersonality=yes",
        "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME CAP_SYS_TTY_CONFIG",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        root_deb,
    ]
    assert "--recursive" not in apt_preflight
    assert "--recursive" not in apt_apply
    assert spu._root_apt_deb_paths(plan) == [Path(root_deb)]
    assert all("staged_package_update.py" not in arg for arg in apt_apply)
    assert all("apt-get" not in arg for arg in apt_apply)
    assert apt_apply[0] == "/usr/bin/systemd-run"
    assert "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK" in apt_apply
    assert "--property=IPAddressDeny=any" in apt_apply
    assert "--property=PrivateNetwork=yes" in apt_apply
    assert "--property=PrivateMounts=yes" in apt_apply
    assert "--property=BindPaths=/run/heim-pc-package-update-captures/20260826T194332Z-1dedf2da5503:/run" in apt_apply
    assert "--property=TemporaryFileSystem=/run" not in apt_apply
    assert "--property=BindReadOnlyPaths=/dev/null:/run/systemd/private /dev/null:/run/dbus/system_bus_socket" in apt_apply
    for prop in (
        "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
        "PrivateDevices=yes", "RestrictNamespaces=yes", "ProtectKernelLogs=yes",
        "ProtectClock=yes", "LockPersonality=yes",
    ):
        assert f"--property={prop}" in apt_apply
    assert not any(arg.startswith("--property=InaccessiblePaths=/proc/1") for arg in apt_apply)
    assert any(arg.startswith("--property=CapabilityBoundingSet=~CAP_SYS_ADMIN") for arg in apt_apply)
    assert apt_apply[apt_apply.index("--") + 1] == "/usr/bin/dpkg"
    assert copy_commands["hash_argv"] == [
        "/usr/bin/sha256sum",
        f"{root_debs}/000-curl-amd64-deadbeef.deb",
        "/var/lib/heim-pc/package-update-stages/20260826T194332Z-1dedf2da5503/snaps/core22_2437.assert",
        "/var/lib/heim-pc/package-update-stages/20260826T194332Z-1dedf2da5503/snaps/core22_2437.snap",
    ]
    assert apply_commands["snap_apply_argvs"] == [
        ["/usr/bin/snap", "ack", "/var/lib/heim-pc/package-update-stages/20260826T194332Z-1dedf2da5503/snaps/core22_2437.assert"],
        ["/usr/bin/snap", "install", "/var/lib/heim-pc/package-update-stages/20260826T194332Z-1dedf2da5503/snaps/core22_2437.snap"],
    ]
    assert all("--dangerous" not in argv for argv in apply_commands["snap_apply_argvs"])
    assert commands["runtime_capture_path"] == "/run/heim-pc-package-update-captures/20260826T194332Z-1dedf2da5503"
    assert commands["root_copy_required_bytes"] == 153
    assert commands["root_stage_safety_margin_bytes"] == 1000
    assert commands["root_capacity_required_bytes"] == 1153
    assert commands["root_capacity_prepare_argv"] == [
        "/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0711",
        "/var/lib/heim-pc/package-update-stages",
    ]
    assert commands["root_capacity_argv"] == [
        "/usr/bin/stat", "-f", "-c", "%a:%S", "/var/lib/heim-pc/package-update-stages"
    ]
    assert commands["cleanup_runtime_capture_argv"] == [
        "/usr/bin/rm", "-rf", "--", "/run/heim-pc-package-update-captures/20260826T194332Z-1dedf2da5503"
    ]


def test_root_staging_capacity_probe_and_readback_are_fail_closed(tmp_path: Path) -> None:
    policy = {
        "staging": {
            "root_root": "/var/lib/heim-pc/package-update-stages",
            "runtime_capture_root": "/run/heim-pc-package-update-captures",
            "root_stage_safety_margin_bytes": 100,
        }
    }
    apt = {"packages": [{"relative_path": "apt/debs/a.deb", "sha256": "a" * 64, "size": 80}]}
    snap = {"packages": [{
        "assert_relative_path": "snap/a.assert", "assert_size": 10,
        "snap_relative_path": "snap/a.snap", "snap_size": 20,
    }]}
    commands = spu._root_commands(
        "20260827T010203Z-123456abcdef", tmp_path / "stage", policy, apt, snap
    )
    assert commands["root_copy_required_bytes"] == 110
    assert commands["root_stage_safety_margin_bytes"] == 100
    assert commands["root_capacity_required_bytes"] == 210
    assert commands["root_capacity_prepare_argv"] == [
        "/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0711",
        "/var/lib/heim-pc/package-update-stages",
    ]
    assert commands["root_capacity_argv"] == [
        "/usr/bin/stat", "-f", "-c", "%a:%S", "/var/lib/heim-pc/package-update-stages"
    ]
    assert spu.parse_root_capacity_readback("100:4096\n", 210) == {
        "required_bytes": 210, "available_bytes": 409600, "sufficient": True
    }
    with pytest.raises(spu.PlanError, match="requires 210 bytes"):
        spu.parse_root_capacity_readback("20:10", 210)
    with pytest.raises(spu.PlanError, match="unexpected root staging filesystem capacity readback"):
        spu.parse_root_capacity_readback("not-a-capacity", 110)


def test_root_capacity_gate_can_provision_empty_base_before_stat_without_releasing_copy(
    tmp_path: Path,
) -> None:
    root_root = tmp_path / "first-run" / "package-update-stages"
    policy = {
        "staging": {
            "root_root": str(root_root),
            "runtime_capture_root": "/run/heim-pc-package-update-captures",
            "root_stage_safety_margin_bytes": 100,
        }
    }
    apt = {"packages": [{"relative_path": "apt/debs/a.deb", "sha256": "a" * 64, "size": 80}]}
    commands = spu._root_commands(
        "20260827T010203Z-123456abcdef", tmp_path / "stage", policy, apt, {"packages": []}
    )
    assert not root_root.exists()
    assert commands["root_capacity_prepare_argv"] == [
        "/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0711",
        str(root_root),
    ]
    assert commands["root_capacity_argv"] == [
        "/usr/bin/stat", "-f", "-c", "%a:%S", str(root_root)
    ]
    for withheld in ("prepare_argv", "copy_apt_argv", "copy_snap_argv", "hash_apt_argv", "hash_snap_argv"):
        assert withheld not in commands


def test_verify_withholds_root_copy_commands_until_capacity_readback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    stage = tmp_path / "verify-capacity"
    stage.mkdir()
    apt = {"packages": [{"name": "curl", "relative_path": "apt/debs/curl.deb", "sha256": "a" * 64, "size": 10}]}
    snap = {"packages": []}
    commands = spu._root_commands("20260827T010203Z-123456abcdef", stage, policy, apt, snap)
    plan = {
        "plan_id": "20260827T010203Z-123456abcdef", "plan_sha256": "f" * 64,
        "created_at_unix": 1, "stage_path": str(stage),
        "baseline": {"uid": os.geteuid(), "dpkg_status_sha256": "status", "apt_source_config": []},
        "apt": apt, "snap": snap, "root_commands": commands, "root_artifact_sha256": {},
    }
    monkeypatch.setattr(spu, "_validate_plan_identity", lambda path, confirmation: (plan, policy, stage, os.geteuid()))
    monkeypatch.setattr(spu.time, "time", lambda: 2)
    monkeypatch.setattr(spu, "_dpkg_status_sha256", lambda: "status")
    monkeypatch.setattr(spu, "_validate_source_config", lambda expected: None)
    monkeypatch.setattr(spu, "_require_broker_handoff_binding", lambda policy: None)
    monkeypatch.setattr(spu, "_validate_stage_artifacts", lambda plan, uid, policy: None)
    monkeypatch.setattr(spu, "_revalidate_apt_provenance", lambda stage, plan, policy, uid: None)
    monkeypatch.setattr(spu, "_revalidate_snap_provenance", lambda stage, plan, policy, uid: None)
    result = spu.verify_plan(stage / "plan.json", "f" * 64)
    assert "root_commands" not in result
    assert result["root_capacity"]["required"] is True
    assert result["root_capacity"]["prepare_argv"] == commands["root_capacity_prepare_argv"]
    assert result["root_capacity"]["argv"] == commands["root_capacity_argv"]
    assert result["root_capacity"]["copy_bytes"] == 10
    assert result["root_capacity"]["safety_margin_bytes"] == policy["staging"]["root_stage_safety_margin_bytes"]
    assert result["root_capacity"]["required_bytes"] == 10 + policy["staging"]["root_stage_safety_margin_bytes"]


def test_capacity_authorization_blocks_before_copy_when_root_stage_space_is_insufficient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    stage = tmp_path / "capacity-block"
    stage.mkdir()
    now = int(spu.time.time())
    apt = {"packages": [{"name": "curl", "relative_path": "apt/debs/curl.deb", "sha256": "a" * 64, "size": 10}]}
    snap = {"packages": []}
    plan = {
        "plan_id": "20260827T010203Z-123456abcdef",
        "plan_sha256": "f" * 64,
        "created_at_unix": now - 1,
        "baseline": {"uid": os.geteuid()},
        "stage_path": str(stage),
        "root_commands": spu._root_commands("20260827T010203Z-123456abcdef", stage, policy, apt, snap),
        "apt": apt,
        "snap": snap,
    }
    monkeypatch.setattr(spu, "_verify_plan_loaded", lambda path, confirmation: ({"age_seconds": 1}, plan, policy))
    evidence_root = tmp_path / "broker-evidence"
    monkeypatch.setattr(spu, "BROKER_OUTPUT_EVIDENCE_ROOT", evidence_root)
    _allow_test_owned_broker_evidence(monkeypatch)
    output = "0:4096"
    evidence = _write_broker_evidence(
        evidence_root,
        argv=plan["root_commands"]["root_capacity_argv"],
        stdout=output,
        request_id="1" * 32,
        timestamp_unix=now,
    )
    with pytest.raises(spu.PlanError, match="destination filesystem has only 0 available"):
        spu.root_capacity_authorize(stage / "plan.json", "f" * 64, output, evidence)
    assert not (stage / "root-capacity.json").exists()


def test_verify_rejects_authenticated_apt_total_over_byte_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stage = tmp_path / "stage"
    (stage / "apt" / "debs").mkdir(parents=True)
    item = {
        "name": "curl", "version": "new", "arch": "amd64",
        "sha256": "a" * 64,
        "repository_size": 2048, "repository_hash_algorithm": "SHA256", "repository_hash": "a" * 64,
        "repository_sha256": "a" * 64,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64,
        "relative_path": "apt/debs/curl.deb",
    }
    plan = {"apt": {"enabled": True, "packages": [item], "authenticated_download_bytes": 2048, "download_bytes": 2048}}
    policy = {"apt": {"enabled": True, "max_packages": 10, "max_download_bytes": 1024}}
    monkeypatch.setattr(spu, "_apt_update_and_candidates", lambda *args: ([], {}, {}, [{"name": "curl", "version": "new", "arch": "amd64"}]))
    monkeypatch.setattr(spu, "_apt_repository_record", lambda options, candidate: {
        "repository_size": 2048, "repository_hash_algorithm": "SHA256", "repository_hash": "a" * 64,
        "repository_sha256": "a" * 64,
        "repository_manifest_sha256": "b" * 64, "repository_uri_sha256": "c" * 64, "repository_filename": "curl.deb",
    })
    with pytest.raises(spu.PlanError, match="exceed policy limit during verification"):
        spu._revalidate_apt_provenance(stage, plan, policy, os.geteuid())


def test_root_hash_readback_is_exact_and_only_then_emits_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    plan_id = "20260827T010203Z-123456abcdef"
    stage = tmp_path / "stage"
    stage.mkdir()
    now = int(spu.time.time())
    apt = {"packages": [{
        "name": "curl", "version": "new", "arch": "amd64",
        "relative_path": "apt/debs/curl.deb", "sha256": "a" * 64, "size": 10,
    }]}
    snap = {"packages": []}
    commands = spu._root_commands(plan_id, stage, policy, apt, snap)
    root_path = str(Path(commands["root_stage"]) / "debs" / "curl.deb")
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": plan_id,
        "plan_sha256": "f" * 64, "policy_path": str((ROOT / "config" / "package-update-policy.v1.json").resolve()),
        "created_at_unix": now - 1,
        "baseline": {"uid": os.geteuid()},
        "stage_path": str(stage), "root_commands": commands, "root_artifact_sha256": {root_path: "a" * 64},
        "apt": apt, "snap": snap,
    }
    plan_path = stage / "plan.json"
    plan_path.write_text(json.dumps(plan))
    monkeypatch.setattr(spu, "_verify_plan_loaded", lambda path, confirmation: ({"age_seconds": 1}, plan, policy))
    evidence_root = tmp_path / "broker-evidence"
    monkeypatch.setattr(spu, "BROKER_OUTPUT_EVIDENCE_ROOT", evidence_root)
    _allow_test_owned_broker_evidence(monkeypatch)

    capacity_output = "1000000:4096"
    capacity_evidence = _write_broker_evidence(
        evidence_root,
        argv=commands["root_capacity_argv"],
        stdout=capacity_output,
        request_id="2" * 32,
        timestamp_unix=now,
    )
    capacity = spu.root_capacity_authorize(
        plan_path, "f" * 64, capacity_output, capacity_evidence
    )
    assert capacity["status"] == "root-capacity-authorized"
    assert capacity["copy_commands"]["copy_apt_argv"] is not None

    hash_argv = capacity["copy_commands"]["hash_argv"]
    hash_output = f"{'a' * 64}  {root_path}\n"
    hash_evidence = _write_broker_evidence(
        evidence_root,
        argv=hash_argv,
        stdout=hash_output,
        request_id="3" * 32,
        timestamp_unix=now,
    )
    result = spu.root_readback_authorize(
        plan_path, "f" * 64, hash_output, hash_evidence
    )
    assert result["status"] == "root-readback-authorized"
    assert result["apply_commands"]["apt_apply_argv"][0] == "/usr/bin/systemd-run"
    assert result["broker_output_evidence"]["request_id"] == "3" * 32

    bad_output = f"{'b' * 64}  {root_path}\n"
    bad_evidence = _write_broker_evidence(
        evidence_root,
        argv=hash_argv,
        stdout=bad_output,
        request_id="4" * 32,
        timestamp_unix=now,
    )
    with pytest.raises(spu.PlanError, match="root artifact hash readback mismatch"):
        spu.root_readback_authorize(plan_path, "f" * 64, bad_output, bad_evidence)

    forged_output = f"{'a' * 64}  {root_path}\n"
    wrong_argv_evidence = _write_broker_evidence(
        evidence_root,
        argv=["/usr/bin/sha256sum", "/wrong"],
        stdout=forged_output,
        request_id="5" * 32,
        timestamp_unix=now,
    )
    with pytest.raises(spu.PlanError, match="different argv"):
        spu.root_readback_authorize(plan_path, "f" * 64, forged_output, wrong_argv_evidence)

def test_sha256sum_readback_rejects_duplicate_or_relative_paths() -> None:
    digest = "a" * 64
    with pytest.raises(spu.PlanError, match="unsafe or duplicate"):
        spu._parse_sha256sum_output(f"{digest}  relative.deb\n")
    with pytest.raises(spu.PlanError, match="unsafe or duplicate"):
        spu._parse_sha256sum_output(f"{digest}  /x\n{digest}  /x\n")


def test_dpkg_state_ignores_caller_dpkg_and_loader_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    class Completed:
        returncode = 0
        stdout = "1.0\tinstall ok installed\n"
        stderr = ""
    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        captured.update(kwargs)
        return Completed()
    for key in ("DPKG_ADMINDIR", "DPKG_ROOT", "DPKG_FORCE", "LD_PRELOAD", "SYSTEMD_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(key, "/tmp/attacker-controlled")
    monkeypatch.setattr(spu.subprocess, "run", fake_run)
    assert spu._dpkg_state("curl", "amd64") == {"version": "1.0", "status": "install ok installed"}
    env = captured["env"]
    assert isinstance(env, dict)
    for key in ("DPKG_ADMINDIR", "DPKG_ROOT", "DPKG_FORCE", "LD_PRELOAD", "SYSTEMD_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        assert key not in env
    assert env["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"


def test_dpkg_state_qualifies_multiarch_identity_and_requires_status(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> dict[str, object]:
        calls.append(argv)
        return {
            "argv": argv, "returncode": 0,
            "stdout": "3.0.2-0ubuntu1.29\tinstall ok installed\n", "stderr": "",
        }

    monkeypatch.setattr(spu, "_run", fake_run)
    assert spu._dpkg_state("libssl3", "amd64") == {
        "version": "3.0.2-0ubuntu1.29", "status": "install ok installed"
    }
    assert "--admindir=/var/lib/dpkg" in calls[-1]
    assert calls[-1][-1] == "libssl3:amd64"
    assert spu._dpkg_version("libssl3:i386", "i386") == "3.0.2-0ubuntu1.29"
    assert calls[-1][-1] == "libssl3:i386"


def test_dpkg_state_rejects_ambiguous_multirow_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        spu,
        "_run",
        lambda argv, **kwargs: {
            "argv": argv, "returncode": 0,
            "stdout": "1.0\tinstall ok installed\n1.0\tinstall ok installed\n", "stderr": "",
        },
    )
    assert spu._dpkg_state("libssl3", "amd64") is None


def test_policy_rejects_dangerous_snap(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["snap"]["allow_dangerous"] = True
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="allow_dangerous"):
        spu.load_policy(path)


def test_policy_requires_broker_network_isolation(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["privileged_broker_network_must_remain_blocked"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="privileged_broker_network_must_remain_blocked"):
        spu.load_policy(path)


def test_policy_requires_read_only_handoff_guard(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["require_broker_read_only_handoff"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_broker_read_only_handoff"):
        spu.load_policy(path)


def test_policy_requires_snap_store_revalidation_and_private_apt_runtime(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    for key in (
        "require_snap_store_artifact_revalidation", "require_apt_apply_private_runtime_namespace",
        "require_root_staging_capacity", "require_reboot_capture",
        "require_apt_apply_kernel_device_isolation", "require_apply_readback_authorization",
        "require_snap_download_byte_cap", "require_snap_download_hard_quota",
        "require_authenticated_apt_preflight_completion", "require_authenticated_apply_completion_evidence",
        "require_postflight_plan_identity",
        "require_privileged_broker_output_evidence", "require_target_downgrade_refusal",
        "require_explicit_activation_semantics",
    ):
        mutated = json.loads(json.dumps(policy))
        mutated["safety"][key] = False
        path = tmp_path / f"{key}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(spu.PolicyError, match=key):
            spu.load_policy(path)


def test_policy_requires_signed_apt_provenance_and_pre_download_cap(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    for key in ("require_signed_apt_artifact_provenance", "require_pre_download_byte_cap"):
        mutated = json.loads(json.dumps(policy))
        mutated["safety"][key] = False
        path = tmp_path / f"{key}.json"
        path.write_text(json.dumps(mutated))
        with pytest.raises(spu.PolicyError, match=key):
            spu.load_policy(path)


def test_policy_requires_explicit_dpkg_apply_guard(tmp_path: Path) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    policy["safety"]["require_dpkg_explicit_apply"] = False
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(spu.PolicyError, match="require_dpkg_explicit_apply"):
        spu.load_policy(path)


def test_handoff_root_must_be_below_declared_broker_bind() -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    assert spu._expand_runtime_root(policy, 1000) == Path(
        "/home/alex/repos/.heim-pc-worktrees/.package-update-handoff"
    )
    policy["staging"]["runtime_root"] = "/run/user/1000/heim-pc-package-updates"
    with pytest.raises(spu.PolicyError, match="broker_bind_root"):
        spu._expand_runtime_root(policy, 1000)


def test_effective_broker_bind_reset_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    output = """[Service]
BindReadOnlyPaths=/one /stale
[Service]
BindReadOnlyPaths=
BindReadOnlyPaths=-/home/alex/repos/.heim-pc-worktrees /other
"""
    monkeypatch.setattr(
        spu,
        "_run",
        lambda argv: {"argv": argv, "returncode": 0, "stdout": output, "stderr": ""},
    )
    assert spu._effective_broker_read_only_bindings() == [
        Path("/home/alex/repos/.heim-pc-worktrees"),
        Path("/other"),
    ]


def test_exact_confirmation_required() -> None:
    plan = {"schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "x"}
    plan["plan_sha256"] = spu._plan_digest(plan)
    spu._validate_confirmation(plan, plan["plan_sha256"])
    with pytest.raises(spu.PlanError, match="confirmation"):
        spu._validate_confirmation(plan, "0" * 64)


def test_postflight_rejects_noncanonical_plan_identity(tmp_path: Path) -> None:
    alternate_policy = tmp_path / "policy.json"
    alternate_policy.write_bytes((ROOT / "config" / "package-update-policy.v1.json").read_bytes())
    stage = tmp_path / "stage"
    stage.mkdir()
    plan = {
        "schema_version": 1, "kind": spu.PLAN_KIND,
        "plan_id": "20260827T010203Z-123456abcdef",
        "policy_path": str(alternate_policy), "policy_sha256": spu._sha256_file(alternate_policy),
        "stage_path": str(stage), "baseline": {"uid": os.geteuid()},
        "apt": {"packages": []}, "snap": {"packages": []},
        "root_commands": {"root_stage": "/var/lib/heim-pc/package-update-stages/x"},
        "root_artifact_sha256": {},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    with pytest.raises(spu.PlanError, match="canonical repository policy"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))


def _write_plan(tmp_path: Path, plan: dict[str, object]) -> Path:
    path = tmp_path / (str(plan["plan_id"]) + ".json")
    path.write_text(json.dumps(plan, sort_keys=True))
    return path


def _stub_postflight_identity(monkeypatch: pytest.MonkeyPatch, plan: dict[str, object]) -> None:
    policy = json.loads((ROOT / "config" / "package-update-policy.v1.json").read_text())
    monkeypatch.setattr(
        spu, "_validate_plan_identity",
        lambda plan_path, confirmation: (plan, policy, Path(str(plan["stage_path"])), os.geteuid()),
    )
    monkeypatch.setattr(
        spu, "_validate_postflight_authorization",
        lambda plan_value, policy_value, uid, paths, apt_preflight_path=None: {
            "status": "test-authenticated", "apt_preflight_evidence": None, "apply_evidence": []
        },
    )


def _postflight_run(
    argv: list[str], *, gpu_returncode: int = 0, gpu_stdout: str = "gpu-ok\n",
    gpu_stderr: str = "", audit_stdout: str = "", audit_stderr: str = "",
) -> dict[str, object]:
    if argv == ["/usr/bin/dpkg", "--admindir=/var/lib/dpkg", "--audit"]:
        return {
            "argv": argv, "returncode": 0,
            "stdout": audit_stdout, "stderr": audit_stderr,
        }
    if argv and argv[0] == "/usr/bin/nvidia-smi":
        return {
            "argv": argv, "returncode": gpu_returncode,
            "stdout": gpu_stdout, "stderr": gpu_stderr,
        }
    raise AssertionError(argv)


def test_broker_apply_evidence_requires_authenticated_preflight_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_root = tmp_path / "apply-evidence"
    evidence_root.mkdir(mode=0o755)
    monkeypatch.setattr(spu, "BROKER_OUTPUT_EVIDENCE_ROOT", evidence_root)
    plan_id = "20260827T010203Z-123456abcdef"
    root_stage = f"/var/lib/heim-pc/package-update-stages/{plan_id}"
    deb = f"{root_stage}/debs/a.deb"
    preflight_argv = [
        "/usr/bin/dpkg", "--simulate", "--refuse-downgrade", "--force-confold",
        "--install", deb,
    ]
    apply_argv = [
        "/usr/bin/systemd-run", "--system", "--wait", "--",
        "/usr/bin/dpkg", "--install", deb,
    ]
    guard = "a" * 64
    now = int(spu.time.time())
    plan = {
        "plan_id": plan_id,
        "baseline": {"uid": os.geteuid()},
        "root_commands": {"root_stage": root_stage},
    }

    def write_completion(
        request_id: str, argv: list[str], timestamp_unix: int, **package_fields: object
    ) -> Path:
        value: dict[str, object] = {
            "schema_version": 1, "kind": spu.BROKER_OUTPUT_EVIDENCE_KIND,
            "request_id": request_id, "reference_sha256": "c" * 64,
            "action": spu.BROKER_POWER_ACTION, "mode": "argv-json",
            "argv_sha256": spu._sha256_json(argv), "cwd_sha256": "d" * 64,
            "peer_uid": os.geteuid(), "peer_unit": spu.BROKER_PEER_UNIT,
            "returncode": 0, "timed_out": False,
            "stdout_sha256": spu._sha256_bytes(b""), "stdout_bytes": 0,
            "stdout_truncated": False, "stderr_truncated": False,
            "timestamp_unix": timestamp_unix,
            **package_fields,
        }
        value["evidence_sha256"] = spu._sha256_json(value)
        path = evidence_root / f"{request_id}.json"
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        path.chmod(0o640)
        return path

    preflight_path = write_completion(
        "b" * 32, preflight_argv, now,
        package_plan_id=plan_id, package_paths=[deb],
        package_preflight_completed=True, package_operation="apt_preflight",
        package_exact_evidence=True,
        package_preflight_guard_evidence_sha256=guard,
    )
    preflight = spu._validate_broker_preflight_evidence(
        preflight_path, expected_argv=preflight_argv, plan=plan,
        guard_evidence_sha256=guard, not_before_unix=now - 1,
        max_age_seconds=60, expected_owner_uid=os.geteuid(),
    )
    apply_path = write_completion(
        "c" * 32, apply_argv, now,
        package_plan_id=plan_id, package_paths=[deb],
        package_apply_completed=True, package_operation="apt_apply",
        package_exact_evidence=True, package_apply_guard_evidence_sha256=guard,
        package_apply_preflight_evidence_sha256=preflight["evidence_sha256"],
    )
    result = spu._validate_broker_apply_evidence(
        apply_path, expected_argv=apply_argv, expected_operation="apt_apply", plan=plan,
        guard_evidence_sha256=guard, not_before_unix=now - 1, max_age_seconds=60,
        expected_preflight_evidence_sha256=str(preflight["evidence_sha256"]),
        preflight_timestamp_unix=int(preflight["timestamp_unix"]),
        expected_owner_uid=os.geteuid(),
    )
    assert result["package_operation"] == "apt_apply"
    with pytest.raises(spu.PlanError, match="lacks the authenticated preflight binding"):
        spu._validate_broker_apply_evidence(
            apply_path, expected_argv=apply_argv, expected_operation="apt_apply", plan=plan,
            guard_evidence_sha256=guard, not_before_unix=now - 1, max_age_seconds=60,
            expected_preflight_evidence_sha256="e" * 64, preflight_timestamp_unix=now,
            expected_owner_uid=os.geteuid(),
        )


def test_postflight_authorization_requires_apt_preflight_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = int(spu.time.time())
    plan_id = "20260827T010203Z-123456abcdef"
    root_stage = f"/var/lib/heim-pc/package-update-stages/{plan_id}"
    deb = f"{root_stage}/debs/a.deb"
    apt_apply = ["/usr/bin/systemd-run", "--wait", deb]
    apt_preflight = ["/usr/bin/dpkg", "--simulate", "--install", deb]
    plan = {
        "plan_id": plan_id, "created_at_unix": now - 1,
        "baseline": {"uid": os.geteuid()},
        "root_commands": {"root_stage": root_stage},
    }
    policy = {"staging": {"max_plan_age_seconds": 60}}
    monkeypatch.setattr(
        spu, "_apply_commands",
        lambda plan_value, policy_value: {"apt_apply_argv": apt_apply, "snap_apply_argvs": []},
    )
    monkeypatch.setattr(
        spu, "_validate_root_readback_receipt",
        lambda plan_value, policy_value, uid: {
            "broker_output_evidence": {"evidence_sha256": "a" * 64},
            "authorized_at_unix": now - 1,
            "apt_apply_preflight_argv": apt_preflight,
            "receipt_sha256": "b" * 64,
        },
    )
    with pytest.raises(spu.PlanError, match="requires authenticated successful APT preflight evidence"):
        spu._validate_postflight_authorization(
            plan, policy, os.geteuid(), [Path("/nonexistent-apply-evidence.json")]
        )


def test_postflight_authorization_rejects_stale_plan_without_apply() -> None:
    policy = {"staging": {"max_plan_age_seconds": 60}}
    plan = {
        "plan_id": "20260827T010203Z-123456abcdef",
        "created_at_unix": int(spu.time.time()) - 61,
        "root_commands": {"root_stage": "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef"},
        "apt": {"packages": []}, "snap": {"packages": []},
    }
    with pytest.raises(spu.PlanError, match="postflight plan age"):
        spu._validate_postflight_authorization(plan, policy, os.geteuid(), [])


def test_postflight_mismatch_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage"
    stage.mkdir()
    capture = tmp_path / "runtime-capture"
    capture.mkdir(mode=0o711)
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{"name": "curl", "arch": "amd64", "version": "wanted", "reboot_marker_capable": False}]},
        "snap": {"packages": []},
        "root_commands": {"runtime_capture_path": str(capture)},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_dpkg_state", lambda name, arch=None: {"version": "actual", "status": "install ok installed"})
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    with pytest.raises(spu.PlanError, match="postflight target mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_apt_matched"] is False
    assert receipt["all_snap_matched"] is True


def test_postflight_preserves_isolated_reboot_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-reboot"
    stage.mkdir()
    capture = tmp_path / "capture-reboot"
    capture.mkdir(mode=0o711)
    (capture / "reboot-required").touch()
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "reboot-capture",
        "policy_path": str(policy_path.resolve()), "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{"name": "curl", "arch": "amd64", "version": "wanted", "reboot_marker_capable": False}]},
        "snap": {"packages": []}, "root_commands": {"runtime_capture_path": str(capture)},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_dpkg_state", lambda name, arch=None: {"version": "wanted", "status": "install ok installed"})
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    result = spu.postflight(plan_path, str(plan["plan_sha256"]))
    assert result["reboot_required"] is True
    assert "isolated-apt-runtime-marker" in result["reboot_required_sources"]


def test_postflight_conservatively_flags_reboot_marker_capable_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-reboot-conservative"
    stage.mkdir()
    capture = tmp_path / "capture-reboot-conservative"
    capture.mkdir(mode=0o711)
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "reboot-conservative",
        "policy_path": str(policy_path.resolve()), "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{"name": "dbus", "arch": "amd64", "version": "wanted", "reboot_marker_capable": True}]},
        "snap": {"packages": []}, "root_commands": {"runtime_capture_path": str(capture)},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_dpkg_state", lambda name, arch=None: {"version": "wanted", "status": "install ok installed"})
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    result = spu.postflight(plan_path, str(plan["plan_sha256"]))
    assert result["reboot_required"] is True
    assert result["reboot_marker_capable_packages"] == ["dbus"]
    assert "planned-reboot-marker-capable-package" in result["reboot_required_sources"]


def test_postflight_fails_if_apt_runtime_capture_was_cleaned_early(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-reboot-missing"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "reboot-missing",
        "policy_path": str(policy_path.resolve()), "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{"name": "curl", "arch": "amd64", "version": "wanted", "reboot_marker_capable": False}]},
        "snap": {"packages": []}, "root_commands": {"runtime_capture_path": str(tmp_path / "missing-capture")},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_dpkg_state", lambda name, arch=None: {"version": "wanted", "status": "install ok installed"})
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    with pytest.raises(spu.PlanError, match="runtime capture is missing"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))


def test_postflight_rejects_target_version_when_dpkg_not_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-half-configured"
    stage.mkdir()
    capture = tmp_path / "capture-half-configured"
    capture.mkdir(mode=0o711)
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "half-configured",
        "policy_path": str(policy_path.resolve()), "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": [{
            "name": "curl", "arch": "amd64", "version": "wanted",
            "reboot_marker_capable": False,
        }]},
        "snap": {"packages": []}, "root_commands": {"runtime_capture_path": str(capture)},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(
        spu, "_dpkg_state",
        lambda name, arch=None: {"version": "wanted", "status": "unpack ok unpacked"},
    )
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    with pytest.raises(spu.PlanError, match="postflight target mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["apt"][0]["installed_version"] == "wanted"
    assert receipt["apt"][0]["installed_status"] == "unpack ok unpacked"
    assert receipt["all_apt_matched"] is False


def test_postflight_rejects_nonempty_dpkg_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-audit"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1, "kind": spu.PLAN_KIND, "plan_id": "audit-mismatch",
        "policy_path": str(policy_path.resolve()), "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage), "apt": {"packages": []}, "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(
        spu, "_run",
        lambda argv, **kwargs: _postflight_run(argv, audit_stdout="package requires configuration\n"),
    )
    with pytest.raises(spu.PlanError, match="dpkg audit mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["dpkg_audit_ok"] is False


def test_postflight_inactive_service_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-service"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "service-mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": []},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(
        spu, "_service_state",
        lambda unit, user: "inactive" if unit == "docker.service" else "active",
    )
    monkeypatch.setattr(spu, "_run", lambda argv, **kwargs: _postflight_run(argv))
    with pytest.raises(spu.PlanError, match="service health mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_system_services_active"] is False
    assert receipt["all_user_services_active"] is True
    assert receipt["nvidia_smi_ok"] is True


def test_postflight_nvidia_failure_writes_receipt_and_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = ROOT / "config" / "package-update-policy.v1.json"
    stage = tmp_path / "stage-nvidia"
    stage.mkdir()
    plan: dict[str, object] = {
        "schema_version": 1,
        "kind": spu.PLAN_KIND,
        "plan_id": "nvidia-mismatch",
        "policy_path": str(policy_path.resolve()),
        "policy_sha256": spu._sha256_file(policy_path),
        "stage_path": str(stage),
        "apt": {"packages": []},
        "snap": {"packages": []},
    }
    plan["plan_sha256"] = spu._plan_digest(plan)
    plan_path = _write_plan(tmp_path, plan)
    _stub_postflight_identity(monkeypatch, plan)
    monkeypatch.setattr(spu, "_service_state", lambda unit, user: "active")
    monkeypatch.setattr(
        spu, "_run",
        lambda argv, **kwargs: _postflight_run(
            argv, gpu_returncode=1, gpu_stdout="", gpu_stderr="gpu failed"
        ),
    )
    with pytest.raises(spu.PlanError, match="NVIDIA health mismatch"):
        spu.postflight(plan_path, str(plan["plan_sha256"]))
    receipt = json.loads((stage / "postflight.json").read_text())
    assert receipt["all_system_services_active"] is True
    assert receipt["all_user_services_active"] is True
    assert receipt["nvidia_smi_ok"] is False
    assert receipt["nvidia_smi"] is None


def test_root_artifact_expectations_bind_destinations() -> None:
    plan = {
        "root_commands": {"root_stage": "/var/lib/heim-pc/package-update-stages/p"},
        "apt": {"packages": [{"relative_path": "apt/debs/a.deb", "sha256": "1" * 64}]},
        "snap": {
            "packages": [
                {
                    "assert_relative_path": "snap/a.assert",
                    "assert_sha256": "2" * 64,
                    "snap_relative_path": "snap/a.snap",
                    "snap_sha256": "3" * 64,
                }
            ]
        },
    }
    assert spu._artifact_expectations(plan) == {
        "/var/lib/heim-pc/package-update-stages/p/debs/a.deb": "1" * 64,
        "/var/lib/heim-pc/package-update-stages/p/snaps/a.assert": "2" * 64,
        "/var/lib/heim-pc/package-update-stages/p/snaps/a.snap": "3" * 64,
    }
